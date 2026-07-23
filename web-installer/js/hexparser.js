// Port a JavaScript de ledgerblue/hexParser.py (Apache-2.0, Ledger)
// Parsea Intel HEX a áreas de memoria { start, data } ordenadas por dirección.

export class IntelHexParser {
  // hexText: contenido del fichero .hex como string
  constructor(hexText) {
    this.bootAddr = 0;
    this.areas = [];
    let startZone = null;
    let startFirst = null;
    let current = null;
    let zoneData = [];

    const flush = () => {
      if (zoneData.length !== 0) {
        this._addArea({ start: startZone * 0x10000 + startFirst, data: Uint8Array.from(zoneData) });
        zoneData = [];
        startZone = null;
        startFirst = null;
        current = null;
      }
    };

    const lines = hexText.split(/\r?\n/);
    for (let lineNumber = 0; lineNumber < lines.length; lineNumber++) {
      const line = lines[lineNumber].trim();
      if (line.length === 0) continue;
      if (line[0] !== ':') throw new Error(`Invalid data at line ${lineNumber + 1}`);
      const data = hexToBytes(line.slice(1));
      const count = data[0];
      const address = (data[1] << 8) + data[2];
      const recordType = data[3];

      // verificación de checksum de línea (el original no la hace; gratis y más seguro)
      let cks = 0;
      for (const b of data) cks = (cks + b) & 0xff;
      if (cks !== 0) throw new Error(`Bad record checksum at line ${lineNumber + 1}`);

      if (recordType === 0x00) {
        if (startZone === null) throw new Error(`Data record but no zone defined at line ${lineNumber + 1}`);
        if (startFirst === null) {
          startFirst = address;
          current = startFirst;
        }
        if (address !== current) {
          this._addArea({ start: startZone * 0x10000 + startFirst, data: Uint8Array.from(zoneData) });
          zoneData = [];
          startFirst = address;
          current = address;
        }
        for (let i = 4; i < 4 + count; i++) zoneData.push(data[i]);
        current += count;
      } else if (recordType === 0x01) {
        flush();
      } else if (recordType === 0x02 || recordType === 0x03) {
        throw new Error(`Unsupported record 0${recordType}`);
      } else if (recordType === 0x04) {
        flush();
        startZone = (data[4] << 8) + data[5];
      } else if (recordType === 0x05) {
        this.bootAddr = ((data[4] & 0xff) * 0x1000000) + ((data[5] & 0xff) << 16) + ((data[6] & 0xff) << 8) + (data[7] & 0xff);
      }
    }
    flush();
  }

  _addArea(area) {
    let i = 0;
    while (i < this.areas.length) {
      if (area.start < this.areas[i].start) break;
      i++;
    }
    this.areas.splice(i, 0, area);
  }

  // añade un área extra (equivale a IntelHexPrinter.addArea; se usa para install params no embebidos)
  addArea(start, data) {
    this._addArea({ start, data });
  }

  getAreas() {
    return this.areas;
  }

  getBootAddr() {
    return this.bootAddr;
  }

  maxAddr() {
    let addr = 0;
    for (const a of this.areas) if (a.start + a.data.length > addr) addr = a.start + a.data.length;
    return addr;
  }

  minAddr() {
    let addr = 0xffffffff;
    for (const a of this.areas) if (a.start < addr) addr = a.start;
    return addr;
  }
}

export function hexToBytes(hex) {
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) throw new Error('Invalid hex string');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
