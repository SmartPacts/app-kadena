// Port a JavaScript de ledgerblue/hexLoader.py (comandos de carga de apps)
// Solo la ruta usada por el instalador Kadena: tlv + install params embebidos en el hex.

import { concat, u32be } from './scp.js';

const LOAD_SEGMENT_CHUNK_HEADER_LENGTH = 3;
const MIN_PADDING_LENGTH = 1;
const SCP_MAC_LENGTH = 0x0e;

function u16be(n) {
  return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);
}

// CRC16-CCITT (poly 0x1021), misma tabla que ledgerblue
const CRC_TABLE = (() => {
  const t = new Uint16Array(256);
  for (let i = 0; i < 256; i++) {
    let crc = i << 8;
    for (let j = 0; j < 8; j++) crc = ((crc << 1) ^ ((crc & 0x8000) ? 0x1021 : 0)) & 0xffff;
    t[i] = crc;
  }
  return t;
})();

export function crc16(data) {
  let crc = 0xffff;
  for (const byte of data) {
    const b = (byte ^ ((crc >> 8) & 0xff)) & 0xff;
    crc = (CRC_TABLE[b] ^ (crc << 8)) & 0xffff;
  }
  return crc;
}

// transport debe ofrecer exchangeApdu(cla, ins, p1, p2, data) -> Uint8Array
// scpSession (opcional): sesión SCP para cifrar/descifrar (null = claro, solo tests)
export class HexLoader {
  constructor(transport, cla = 0xe0, scpSession = null, sha256stream = null) {
    this.transport = transport;
    this.cla = cla;
    this.scp = scpSession;
    this.createappParams = null;
    this.maxMtu = Math.min(0xfe, this.scp ? transport.apduMaxDataSize() & 0xf0 : transport.apduMaxDataSize());
    this.sha256stream = sha256stream; // instancia con .update(bytes) para hash de la app
  }

  async exchange(ins, p1, p2, data) {
    const wrapped = this.scp ? this.scp.wrap(data) : data;
    const resp = await this.transport.exchangeApdu(this.cla, ins, p1, p2, wrapped);
    return this.scp ? this.scp.unwrap(resp) : resp;
  }

  async selectSegment(baseAddress) {
    await this.exchange(0x00, 0x00, 0x00, concat(new Uint8Array([0x05]), u32be(baseAddress)));
  }

  async loadSegmentChunk(offset, chunk) {
    await this.exchange(0x00, 0x00, 0x00, concat(new Uint8Array([0x06]), u16be(offset), chunk));
  }

  async flushSegment() {
    await this.exchange(0x00, 0x00, 0x00, new Uint8Array([0x07]));
  }

  async crcSegment(offsetSegment, lengthSegment, crcExpected) {
    await this.exchange(0x00, 0x00, 0x00, concat(new Uint8Array([0x08]), u16be(offsetSegment), u32be(lengthSegment), u16be(crcExpected)));
  }

  async createApp(codeLength, apiLevel, dataLength, installParamsLength, flags, bootOffset) {
    this.createappParams = concat(new Uint8Array([apiLevel]), u32be(codeLength), u32be(dataLength), u32be(installParamsLength), u32be(flags), u32be(bootOffset));
    await this.exchange(0x00, 0x00, 0x00, concat(new Uint8Array([0x0b]), this.createappParams));
  }

  async deleteApp(appName) {
    const nameBytes = typeof appName === 'string' ? new TextEncoder().encode(appName) : appName;
    await this.exchange(0x00, 0x00, 0x00, concat(new Uint8Array([0x0c]), new Uint8Array([nameBytes.length]), nameBytes));
  }

  async commit(signature = null) {
    let data = new Uint8Array([0x09]);
    if (signature) data = concat(data, new Uint8Array([signature.length]), signature);
    await this.exchange(0x00, 0x00, 0x00, data);
  }

  // hexFile: IntelHexParser. Streamea la app al dispositivo (ruta tlv, relative=true).
  async load(hexFile, { targetId, targetVersion = '', maxLengthPerApdu = 0xf0, doCRC = true, onProgress = () => {} } = {}) {
    if (maxLengthPerApdu > this.maxMtu) maxLengthPerApdu = this.maxMtu;
    const initialAddress = hexFile.minAddr();

    if (targetId !== undefined && (targetId & 0xf) > 3) {
      if (this.sha256stream) this.sha256stream.update(concat(u32be(targetId), new TextEncoder().encode(targetVersion)));
    }
    if (this.createappParams && this.sha256stream) this.sha256stream.update(this.createappParams);

    const total = hexFile.getAreas().reduce((n, a) => n + a.data.length, 0);
    let sent = 0;

    for (const area of hexFile.getAreas()) {
      const startAddress = area.start - initialAddress;
      const data = area.data;
      await this.selectSegment(startAddress);
      if (data.length === 0) continue;
      if (data.length > 0x10000) throw new Error('Invalid data size for loader');
      const crc = crc16(data);
      let offset = 0;
      let length = data.length;
      while (length > 0) {
        let chunkLen;
        const maxChunk = maxLengthPerApdu - LOAD_SEGMENT_CHUNK_HEADER_LENGTH - MIN_PADDING_LENGTH - SCP_MAC_LENGTH;
        if (length > maxChunk) {
          chunkLen = maxChunk;
          if (chunkLen % 16 !== 0) chunkLen -= chunkLen % 16;
        } else {
          chunkLen = length;
        }
        const chunk = data.slice(offset, offset + chunkLen);
        if (this.sha256stream) this.sha256stream.update(chunk);
        await this.loadSegmentChunk(offset, chunk);
        offset += chunkLen;
        length -= chunkLen;
        sent += chunkLen;
        onProgress(sent / total);
      }
      await this.flushSegment();
      if (doCRC) await this.crcSegment(0, data.length, crc);
    }
  }
}
