import { connect } from 'cloudflare:sockets';

// ============ 类型稳定常量 ============
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
const WS_BACKOFF_MS = 2;
const CONNECT_TIMEOUT = 2000;

const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

// ============ 单态对象工厂（固定形状） ============
function ParseResult(host, end, ok) {
  this.host = host;
  this.end = end | 0;      // SMI优化
  this.ok = !!ok;
}

function DecodeResult(data, ok) {
  this.data = data;
  this.ok = !!ok;
}

const PARSE_FAIL = Object.freeze(new ParseResult('', 0, false));
const DECODE_FAIL = Object.freeze(new DecodeResult(null, false));

// ============ 预编译响应（避免闭包） ============
const RESP_101 = (ws) => new Response(null, { status: 101, webSocket: ws });
const RESP_400 = new Response(null, { status: 400 });
const RESP_403 = new Response(null, { status: 403 });
const RESP_426 = new Response(null, { status: 426, headers: { Upgrade: 'websocket' } });
const RESP_502 = new Response(null, { status: 502 });

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
  const end4 = len & ~3;
  
  for (let i = 0; i < end4; i += 4) {
    arr[i] = binary.charCodeAt(i);
    arr[i + 1] = binary.charCodeAt(i + 1);
    arr[i + 2] = binary.charCodeAt(i + 2);
    arr[i + 3] = binary.charCodeAt(i + 3);
  }
  for (let i = end4; i < len; i++) {
    arr[i] = binary.charCodeAt(i);
  }
  
  return new DecodeResult(arr, true);
}

// ============ UUID 验证（位运算单态） ============
function verifyUUID(data, offset) {
  const o = offset | 0;
  return (
    ((data[o] ^ UUID[0]) | (data[o + 1] ^ UUID[1]) |
     (data[o + 2] ^ UUID[2]) | (data[o + 3] ^ UUID[3])) === 0 &&
    ((data[o + 4] ^ UUID[4]) | (data[o + 5] ^ UUID[5]) |
     (data[o + 6] ^ UUID[6]) | (data[o + 7] ^ UUID[7])) === 0 &&
    ((data[o + 8] ^ UUID[8]) | (data[o + 9] ^ UUID[9]) |
     (data[o + 10] ^ UUID[10]) | (data[o + 11] ^ UUID[11])) === 0 &&
    ((data[o + 12] ^ UUID[12]) | (data[o + 13] ^ UUID[13]) |
     (data[o + 14] ^ UUID[14]) | (data[o + 15] ^ UUID[15])) === 0
  );
}

// ============ 地址解析（分支预测友好） ============
function parseAddress(data, offset, dataLen) {
  const atype = data[offset];
  const o = offset | 0;

  if (atype === ATYPE_IPV4) {
    const end = o + 5;
    if (end > dataLen) return PARSE_FAIL;
    const o1 = o + 1;
    return new ParseResult(
      `${data[o1]}.${data[o1 + 1]}.${data[o1 + 2]}.${data[o1 + 3]}`,
      end,
      true
    );
  }

  if (atype === ATYPE_DOMAIN) {
    if (o + 2 > dataLen) return PARSE_FAIL;
    const domainLen = data[o + 1] | 0;
    const end = o + 2 + domainLen;
    if (end > dataLen) return PARSE_FAIL;
    return new ParseResult(
      textDecoder.decode(data.subarray(o + 2, end)),
      end,
      true
    );
  }

  if (atype === ATYPE_IPV6) {
    const end = o + 17;
    if (end > dataLen) return PARSE_FAIL;
    const dv = new DataView(data.buffer, data.byteOffset + o + 1, 16);
    const parts = [
      dv.getUint16(0).toString(16),
      dv.getUint16(2).toString(16),
      dv.getUint16(4).toString(16),
      dv.getUint16(6).toString(16),
      dv.getUint16(8).toString(16),
      dv.getUint16(10).toString(16),
      dv.getUint16(12).toString(16),
      dv.getUint16(14).toString(16)
    ];
    return new ParseResult(parts.join(':'), end, true);
  }

  return PARSE_FAIL;
}

// ============ 超时控制（避免闭包捕获） ============
function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const tid = setTimeout(reject, ms);
    promise.then(
      (v) => { clearTimeout(tid); resolve(v); },
      (e) => { clearTimeout(tid); reject(e); }
    );
  });
}

// ============ TCP 连接 ============
function connectTCP(host, port, fallback) {
  const socket = connect(
    { 
      hostname: fallback ? PROXY_HOST : host, 
      port: fallback ? PROXY_PORT : port 
    },
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
  const frame = new Uint8Array(2 + chunkLen);
  frame[0] = 0x00;
  frame[1] = 0x00;
  frame.set(chunk, 2);
  return frame;
}

// ============ 上行管道 ============
function createUplink(state, initial, writable) {
  const writer = writable.getWriter();
  let chain = Promise.resolve();

  function write(chunk) {
    chain = chain.then(() => {
      if (state.closed) return;
      return writer.write(chunk);
    }).catch(() => {
      state.shutdown();
    });
  }

  if (initial.length > 0) write(initial);

  return function onMessage(ev) {
    if (!state.closed) write(new Uint8Array(ev.data));
  };
}

// ============ 下行管道 ============
function createDownlink(state, ws, readable) {
  const reader = readable.getReader();
  let first = true;

  function pump() {
    if (state.closed) {
      try { reader.releaseLock(); } catch {}
      return;
    }

    if (ws.bufferedAmount > WS_HIGH_WATER) {
      setTimeout(pump, WS_BACKOFF_MS);
      return;
    }

    reader.read().then(
      (result) => {
        if (result.done || state.closed) {
          state.shutdown();
          try { reader.releaseLock(); } catch {}
          return;
        }

        const chunk = first ? buildFirstFrame(result.value) : result.value;
        first = false;
        ws.send(chunk);
        pump();
      },
      () => {
        state.shutdown();
        try { reader.releaseLock(); } catch {}
      }
    );
  }

  pump();
}

// ============ VLESS协议解析 ============
function parseVLESSRequest(data) {
  const dataLen = data.length | 0;

  if (dataLen < 22 || data[0] !== 0x00) return null;
  if (!verifyUUID(data, 1)) return null;

  const addonsLen = data[17] | 0;
  const cmdOffset = (18 + addonsLen) | 0;

  if (cmdOffset + 3 > dataLen) return null;
  const cmd = data[cmdOffset] | 0;
  if ((cmd & 0xFE) !== 0) return null;

  const port = (data[cmdOffset + 1] << 8) | data[cmdOffset + 2];

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
    if (req.headers.get('Upgrade') !== 'websocket') return RESP_426;

    const protocol = req.headers.get('Sec-WebSocket-Protocol');
    if (!protocol) return RESP_400;

    const decoded = decodeBase64(protocol);
    if (!decoded.ok) return RESP_400;

    const vlessReq = parseVLESSRequest(decoded.data);
    if (!vlessReq) return RESP_403;
    if (vlessReq.cmd !== 1) return RESP_400;

    let tcp;
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

    return RESP_101(client);
  }
};
