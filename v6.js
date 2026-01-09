import { connect } from 'cloudflare:sockets';

// ============ 预编译常量 ============
const UUID = new Uint8Array([
  0x55, 0xd9, 0xec, 0x38, 0x1b, 0x8a, 0x45, 0x4b,
  0x98, 0x1a, 0x6a, 0xcf, 0xe8, 0xf5, 0x6d, 0x8c
]);
const PROXY_HOST = 'sjc.o00o.ooo';
const PROXY_PORT = 443;

const ATYPE_IPV4 = 1;
const ATYPE_DOMAIN = 2;
const ATYPE_IPV6 = 3;

const WS_HIGH_WATER = 49152;
const WS_LOW_WATER = 24576;
const PUMP_MIN = 2;
const PUMP_MAX = 8;
const CONNECT_TIMEOUT = 2000;

const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

// ============ 固定形状对象工厂 ============
function ParseResult(host, end, ok) {
  this.host = host;
  this.end = end | 0;
  this.ok = !!ok;
}

function DecodeResult(data, ok) {
  this.data = data;
  this.ok = !!ok;
}

const PARSE_FAIL = new ParseResult('', 0, false);
const DECODE_FAIL = new DecodeResult(null, false);

// ============ 预分配响应对象 ============
const RESP_400 = new Response(null, { status: 400 });
const RESP_403 = new Response(null, { status: 403 });
const RESP_426 = new Response(null, { status: 426, headers: { Upgrade: 'websocket' } });
const RESP_502 = new Response(null, { status: 502 });

function createResp101(ws) {
  return new Response(null, { status: 101, webSocket: ws });
}

// ============ Base64 解码（类型稳定） ============
function decodeBase64(str) {
  const cleaned = str.replace(/-/g, '+').replace(/_/g, '/');
  let binary;
  try {
    binary = atob(cleaned);
  } catch {
    return DECODE_FAIL;
  }
  
  const len = binary.length | 0;
  const arr = new Uint8Array(len);
  const end4 = (len & ~3) | 0;
  
  let i = 0;
  while (i < end4) {
    arr[i] = binary.charCodeAt(i) | 0;
    arr[i + 1] = binary.charCodeAt(i + 1) | 0;
    arr[i + 2] = binary.charCodeAt(i + 2) | 0;
    arr[i + 3] = binary.charCodeAt(i + 3) | 0;
    i = (i + 4) | 0;
  }
  while (i < len) {
    arr[i] = binary.charCodeAt(i) | 0;
    i = (i + 1) | 0;
  }
  
  return new DecodeResult(arr, true);
}

// ============ UUID 验证（整数运算） ============
function verifyUUID(data, offset) {
  const o = offset | 0;
  const d = data;
  const u = UUID;
  
  return (
    (((d[o] ^ u[0]) | (d[o + 1] ^ u[1]) | (d[o + 2] ^ u[2]) | (d[o + 3] ^ u[3])) | 0) === 0 &&
    (((d[o + 4] ^ u[4]) | (d[o + 5] ^ u[5]) | (d[o + 6] ^ u[6]) | (d[o + 7] ^ u[7])) | 0) === 0 &&
    (((d[o + 8] ^ u[8]) | (d[o + 9] ^ u[9]) | (d[o + 10] ^ u[10]) | (d[o + 11] ^ u[11])) | 0) === 0 &&
    (((d[o + 12] ^ u[12]) | (d[o + 13] ^ u[13]) | (d[o + 14] ^ u[14]) | (d[o + 15] ^ u[15])) | 0) === 0
  );
}

// ============ 地址解析（单态优化） ============
function parseIPv4(data, offset, dataLen) {
  const end = (offset + 5) | 0;
  if (end > dataLen) return PARSE_FAIL;
  const o1 = (offset + 1) | 0;
  const a = data[o1] | 0;
  const b = data[o1 + 1] | 0;
  const c = data[o1 + 2] | 0;
  const d = data[o1 + 3] | 0;
  return new ParseResult(`${a}.${b}.${c}.${d}`, end, true);
}

function parseDomain(data, offset, dataLen) {
  if ((offset + 2) > dataLen) return PARSE_FAIL;
  const domainLen = data[offset + 1] | 0;
  const end = (offset + 2 + domainLen) | 0;
  if (end > dataLen) return PARSE_FAIL;
  const host = textDecoder.decode(data.subarray(offset + 2, end));
  return new ParseResult(host, end, true);
}

function parseIPv6(data, offset, dataLen) {
  const end = (offset + 17) | 0;
  if (end > dataLen) return PARSE_FAIL;
  const dv = new DataView(data.buffer, data.byteOffset + offset + 1, 16);
  const p0 = dv.getUint16(0, false).toString(16);
  const p1 = dv.getUint16(2, false).toString(16);
  const p2 = dv.getUint16(4, false).toString(16);
  const p3 = dv.getUint16(6, false).toString(16);
  const p4 = dv.getUint16(8, false).toString(16);
  const p5 = dv.getUint16(10, false).toString(16);
  const p6 = dv.getUint16(12, false).toString(16);
  const p7 = dv.getUint16(14, false).toString(16);
  const host = `${p0}:${p1}:${p2}:${p3}:${p4}:${p5}:${p6}:${p7}`;
  return new ParseResult(host, end, true);
}

function parseAddress(data, offset, dataLen) {
  const atype = data[offset] | 0;
  
  if (atype === ATYPE_IPV4) {
    return parseIPv4(data, offset, dataLen);
  }
  if (atype === ATYPE_DOMAIN) {
    return parseDomain(data, offset, dataLen);
  }
  if (atype === ATYPE_IPV6) {
    return parseIPv6(data, offset, dataLen);
  }
  
  return PARSE_FAIL;
}

// ============ 超时控制 ============
function withTimeout(promise, ms) {
  let tid = 0;
  const timeoutPromise = new Promise((_, reject) => {
    tid = setTimeout(() => reject(new Error('timeout')), ms) | 0;
  });
  
  return Promise.race([promise, timeoutPromise]).finally(() => {
    clearTimeout(tid);
  });
}

// ============ TCP 连接 ============
function connectTCP(host, port, fallback) {
  const hostname = fallback ? PROXY_HOST : host;
  const targetPort = fallback ? PROXY_PORT : port;
  const socket = connect(
    { hostname: hostname, port: targetPort | 0 },
    { allowHalfOpen: false }
  );
  return withTimeout(socket.opened, CONNECT_TIMEOUT).then(() => socket);
}

// ============ 连接状态（固定形状） ============
function State() {
  this.closed = false;
  this.ws = null;
  this.tcp = null;
}

State.prototype.init = function(ws, tcp) {
  this.ws = ws;
  this.tcp = tcp;
};

State.prototype.shutdown = function() {
  if (this.closed) return;
  this.closed = true;
  const ws = this.ws;
  const tcp = this.tcp;
  this.ws = null;
  this.tcp = null;
  
  if (ws !== null) {
    try { ws.close(); } catch {}
  }
  if (tcp !== null) {
    try { tcp.close(); } catch {}
  }
};

// ============ VLESS响应头 ============
const VLESS_RESPONSE_HEADER = new Uint8Array([0x00, 0x00]);

function buildFirstFrame(chunk) {
  const chunkLen = chunk.length | 0;
  const frameLen = (2 + chunkLen) | 0;
  const frame = new Uint8Array(frameLen);
  frame[0] = 0x00;
  frame[1] = 0x00;
  frame.set(chunk, 2);
  return frame;
}

// ============ 上行管道（固定形状） ============
function UplinkContext(state, writer) {
  this.state = state;
  this.writer = writer;
  this.writeChain = Promise.resolve();
}

UplinkContext.prototype.push = function(chunk) {
  if (this.state.closed) return;
  
  const self = this;
  const writer = this.writer;
  const state = this.state;
  
  this.writeChain = this.writeChain
    .then(() => {
      if (state.closed) return;
      return writer.ready;
    })
    .then(() => {
      if (state.closed) return;
      return writer.write(chunk);
    })
    .catch(() => {
      state.shutdown();
    });
};

function createUplink(state, initial, writable) {
  const writer = writable.getWriter();
  const ctx = new UplinkContext(state, writer);
  
  const initialLen = initial.length | 0;
  if (initialLen > 0) {
    ctx.push(initial);
  }

  return function onMessage(ev) {
    const data = new Uint8Array(ev.data);
    ctx.push(data);
  };
}

// ============ 下行管道（固定形状） ============
function DownlinkContext(state, ws, reader) {
  this.state = state;
  this.ws = ws;
  this.reader = reader;
  this.first = true;
  this.prefetch = null;
}

DownlinkContext.prototype.pump = function() {
  const self = this;
  const state = this.state;
  const ws = this.ws;
  const reader = this.reader;
  
  (async function pumpLoop() {
    try {
      while (!state.closed) {
        let buffered = (ws.bufferedAmount | 0);
        
        while (buffered > WS_HIGH_WATER && !state.closed) {
          await new Promise(r => queueMicrotask(r));
          buffered = (ws.bufferedAmount | 0);
        }
        
        if (state.closed) break;

        const quantum = buffered < WS_LOW_WATER ? PUMP_MAX : PUMP_MIN;
        
        let i = 0;
        while (i < quantum && !state.closed) {
          const reading = self.prefetch !== null ? self.prefetch : reader.read();
          self.prefetch = null;
          
          const result = await reading;
          
          if (result.done || state.closed) {
            state.shutdown();
            return;
          }
          
          const nextI = (i + 1) | 0;
          if (nextI < quantum) {
            self.prefetch = reader.read();
          }
          
          const value = result.value;
          const chunk = self.first ? buildFirstFrame(value) : value;
          self.first = false;
          ws.send(chunk);
          
          buffered = (ws.bufferedAmount | 0);
          if (buffered > WS_HIGH_WATER) break;
          
          i = nextI;
        }
      }
    } catch {
      state.shutdown();
    } finally {
      try { reader.releaseLock(); } catch {}
    }
  })();
};

function createDownlink(state, ws, readable) {
  const reader = readable.getReader();
  const ctx = new DownlinkContext(state, ws, reader);
  ctx.pump();
}

// ============ VLESS协议解析 ============
function parseVLESSRequest(data) {
  const dataLen = data.length | 0;

  if (dataLen < 22 || data[0] !== 0x00) return null;
  if (!verifyUUID(data, 1)) return null;

  const addonsLen = data[17] | 0;
  const cmdOffset = (18 + addonsLen) | 0;

  if ((cmdOffset + 3) > dataLen) return null;
  const cmd = data[cmdOffset] | 0;
  if (((cmd & 0xFE) | 0) !== 0) return null;

  const port = ((data[cmdOffset + 1] << 8) | data[cmdOffset + 2]) | 0;

  const addrOffset = (cmdOffset + 3) | 0;
  if (addrOffset >= dataLen) return null;

  const addr = parseAddress(data, addrOffset, dataLen);
  if (!addr.ok) return null;

  return {
    cmd: cmd,
    port: port,
    host: addr.host,
    dataOffset: addr.end
  };
}

// ============ 主处理器 ============
export default {
  async fetch(req) {
    const upgradeHeader = req.headers.get('Upgrade');
    if (upgradeHeader !== 'websocket') return RESP_426;

    const protocol = req.headers.get('Sec-WebSocket-Protocol');
    if (protocol === null) return RESP_400;

    const decoded = decodeBase64(protocol);
    if (!decoded.ok) return RESP_400;

    const vlessReq = parseVLESSRequest(decoded.data);
    if (vlessReq === null) return RESP_403;
    
    const cmd = vlessReq.cmd | 0;
    if (cmd !== 1) return RESP_400;

    let tcp = null;
    try {
      tcp = await connectTCP(vlessReq.host, vlessReq.port, false);
    } catch {
      try {
        tcp = await connectTCP(vlessReq.host, vlessReq.port, true);
      } catch {
        return RESP_502;
      }
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();

    const state = new State();
    state.init(server, tcp);

    const dataLen = decoded.data.length | 0;
    const dataOffset = vlessReq.dataOffset | 0;
    const initial = dataLen > dataOffset 
      ? decoded.data.subarray(dataOffset) 
      : EMPTY_BYTES;

    const onMessage = createUplink(state, initial, tcp.writable);
    server.addEventListener('message', onMessage);
    server.addEventListener('close', () => state.shutdown());
    server.addEventListener('error', () => state.shutdown());
    createDownlink(state, server, tcp.readable);

    return createResp101(client);
  }
};
