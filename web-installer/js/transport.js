// Transporte WebHID para Ledger: framing HID de 64 bytes (canal + tag 0x05 + secuencia)
// Equivalente al protocolo de ledgerblue/comm.py y @ledgerhq/hw-transport-webhid.

const LEDGER_VENDOR_ID = 0x2c97;
const PACKET_SIZE = 64;
const TAG_APDU = 0x05;

const SW_MESSAGES = {
  0x9000: null,
  0x6985: { es: 'Operación denegada en el dispositivo (¿rechazaste la petición?)', en: 'Operation denied on device (did you reject the request?)' },
  0x5501: { es: 'Operación cancelada por el usuario', en: 'Operation cancelled by user' },
  0x6a80: { es: 'Datos inválidos', en: 'Invalid data' },
  0x6a84: { es: 'Espacio insuficiente en el dispositivo: borra alguna app e inténtalo de nuevo', en: 'Not enough space on device: delete an app and retry' },
  0x6a85: { es: 'Espacio insuficiente en el dispositivo: borra alguna app e inténtalo de nuevo', en: 'Not enough space on device: delete an app and retry' },
  0x6d00: { es: 'Comando no soportado (¿está el dispositivo en la pantalla principal?)', en: 'Command not supported (is the device on the dashboard?)' },
  0x6e00: { es: 'Clase de comando no soportada (¿está el dispositivo en la pantalla principal?)', en: 'Command class not supported (is the device on the dashboard?)' },
  0x5515: { es: 'El dispositivo está bloqueado: desbloquéalo con el PIN', en: 'Device is locked: unlock it with your PIN' },
};

export class StatusWordError extends Error {
  constructor(sw) {
    const hex = sw.toString(16).padStart(4, '0');
    super(`SW 0x${hex}`);
    this.sw = sw;
    this.messages = SW_MESSAGES[sw] || null;
  }
}

export class WebHidTransport {
  constructor(device) {
    this.device = device;
    this.channel = Math.floor(Math.random() * 0xefff) + 0x1000;
    this.pending = [];
    this.waiter = null;
    device.addEventListener('inputreport', (ev) => {
      this.pending.push(new Uint8Array(ev.data.buffer.slice(0)));
      if (this.waiter) {
        const w = this.waiter;
        this.waiter = null;
        w();
      }
    });
  }

  static isSupported() {
    return typeof navigator !== 'undefined' && !!navigator.hid;
  }

  // debe llamarse desde un gesto del usuario (clic)
  static async request() {
    const devices = await navigator.hid.requestDevice({ filters: [{ vendorId: LEDGER_VENDOR_ID }] });
    if (!devices || devices.length === 0) throw new Error('no-device-selected');
    const device = devices[0];
    if (!device.opened) await device.open();
    return new WebHidTransport(device);
  }

  async close() {
    try {
      await this.device.close();
    } catch {}
  }

  apduMaxDataSize() {
    return 240;
  }

  async _nextReport() {
    while (this.pending.length === 0) {
      await new Promise((resolve) => {
        this.waiter = resolve;
      });
    }
    return this.pending.shift();
  }

  async exchangeApdu(cla, ins, p1, p2, data) {
    const apdu = new Uint8Array(5 + data.length);
    apdu.set([cla, ins, p1, p2, data.length]);
    apdu.set(data, 5);

    // envío: primer frame lleva la longitud total (2B BE) delante
    const payload = new Uint8Array(2 + apdu.length);
    payload[0] = (apdu.length >> 8) & 0xff;
    payload[1] = apdu.length & 0xff;
    payload.set(apdu, 2);

    let seq = 0;
    for (let off = 0; off < payload.length; off += PACKET_SIZE - 5) {
      const frame = new Uint8Array(PACKET_SIZE);
      frame[0] = (this.channel >> 8) & 0xff;
      frame[1] = this.channel & 0xff;
      frame[2] = TAG_APDU;
      frame[3] = (seq >> 8) & 0xff;
      frame[4] = seq & 0xff;
      frame.set(payload.slice(off, off + PACKET_SIZE - 5), 5);
      await this.device.sendReport(0, frame);
      seq++;
    }

    // recepción: reensamblar frames hasta cubrir la longitud anunciada
    let expected = null;
    let received = new Uint8Array(0);
    let rseq = 0;
    while (expected === null || received.length < expected) {
      const report = await this._nextReport();
      const frame = report.length === PACKET_SIZE + 1 ? report.slice(1) : report; // algunos SO anteponen reportId
      const channel = (frame[0] << 8) | frame[1];
      if (channel !== this.channel) continue;
      if (frame[2] !== TAG_APDU) throw new Error(`Bad tag 0x${frame[2].toString(16)}`);
      const s = (frame[3] << 8) | frame[4];
      if (s !== rseq) throw new Error(`Bad sequence ${s} != ${rseq}`);
      rseq++;
      let body;
      if (s === 0) {
        expected = (frame[5] << 8) | frame[6];
        body = frame.slice(7);
      } else {
        body = frame.slice(5);
      }
      const merged = new Uint8Array(received.length + body.length);
      merged.set(received);
      merged.set(body, received.length);
      received = merged;
    }

    const resp = received.slice(0, expected);
    if (resp.length < 2) throw new Error('Truncated response');
    const sw = (resp[resp.length - 2] << 8) | resp[resp.length - 1];
    if (sw !== 0x9000) throw new StatusWordError(sw);
    return resp.slice(0, resp.length - 2);
  }
}
