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

const WS_HIGH_WATER = 32768;
const BATCH_SIZE = 8;
const BATCH_BYTES = 65536;
const CONNECT_TIMEOUT = 2000;

const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

// ============ 单态对象工厂 ============
function ParseResult(host, end, ok) {
  this.host = host;
  this.end = end | 0;
  this.ok = !!ok;
}

function DecodeResult(data, ok) {
  this.data = data;
  this.ok = !!ok;
}

const PARSE_FAIL = Object.freeze(new ParseResult('', 0, false));
const DECODE_FAIL = Object.freeze(new DecodeResult(null, false));

const RESP_101 = (ws) => new Response(null, { status: 101, webSocket: ws });
const RESP_400 = new Response(null, { status: 400 });
const RESP_403 = new Response(null, { status: 403 });
const RESP_426 = new Response(null, { status: 426, headers: { Upgrade: 'websocket' } });
const RESP_502 = new Response(null, { status: 502 });

// ============ Base64 解码 ============
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
  
  let i = 0;
  for (; i < end4; i += 4) {
    arr[i] = binary.charCodeAt(i);
    arr[i + 1] = binary.charCodeAt(i + 1);
    arr[i + 2] = binary.charCodeAt(i + 2);
    arr[i + 3] = binary.charCodeAt(i + 3);
  }
  for (; i < len; i = i + 1 | 0) {
    arr[i] = binary.charCodeAt(i);
  }
  
  return new DecodeResult(arr, true);
}

// ============ UUID 验证 ============
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

// ============ 地址解析 ============
function parseAddress(data, offset, dataLen) {
  const atype = data[offset] | 0;
  const o = offset | 0;

  if (atype === ATYPE_IPV4) {
    const end = o + 5 | 0;
    if (end > dataLen) return PARSE_FAIL;
    const o1 = o + 1 | 0;
    const a = data[o1] | 0;
    const b = data[o1 + 1] | 0;
    const c = data[o1 + 2] | 0;
    const d = data[o1 + 3] | 0;
    return new ParseResult(`${a}.${b}.${c}.${d}`, end, true);
  }

  if (atype === ATYPE_DOMAIN) {
    if (o + 2 > dataLen) return PARSE_FAIL;
    const domainLen = data[o + 1] | 0;
    const end = o + 2 + domainLen | 0;
    if (end > dataLen) return PARSE_FAIL;
    return new ParseResult(
      textDecoder.decode(data.subarray(o + 2, end)),
      end,
      true
    );
  }

  if (atype === ATYPE_IPV6) {
    const end = o + 17 | 0;
    if (end > dataLen) return PARSE_FAIL;
    const dv = new DataView(data.buffer, data.byteOffset + o + 1, 16);
    const p0 = dv.getUint16(0).toString(16);
    const p1 = dv.getUint16(2).toString(16);
    const p2 = dv.getUint16(4).toString(16);
    const p3 = dv.getUint16(6).toString(16);
    const p4 = dv.getUint16(8).toString(16);
    const p5 = dv.getUint16(10).toString(16);
    const p6 = dv.getUint16(12).toString(16);
    const p7 = dv.getUint16(14).toString(16);
    return new ParseResult(
      `${p0}:${p1}:${p2}:${p3}:${p4}:${p5}:${p6}:${p7}`,
      end,
      true
    );
  }

  return PARSE_FAIL;
}

// ============ 超时控制 ============
function withTimeout(promise, ms) {
  let tid = 0;
  return new Promise((resolve, reject) => {
    tid = setTimeout(reject, ms);
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
  const frameLen = 2 + chunkLen | 0;
  const frame = new Uint8Array(frameLen);
  frame[0] = 0x00;
  frame[1] = 0x00;
  frame.set(chunk, 2);
  return frame;
}

// ============ 上行管道上下文（固定形状） ============
function UplinkContext(state, writer) {
  this.state = state;
  this.writer = writer;
  this.queue = [];
  this.flushScheduled = false;
}

UplinkContext.prototype.scheduleFlush = function() {
  if (!this.flushScheduled) {
    this.flushScheduled = true;
    const self = this;
    queueMicrotask(() => self.flush());
  }
};

UplinkContext.prototype.flush = function() {
  const state = this.state;
  const queue = this.queue;
  
  if (state.closed || queue.length === 0) {
    this.flushScheduled = false;
    return;
  }

  let batchCount = 0;
  let batchBytes = 0;
  let i = 0;
  
  while (i < queue.length && batchCount < BATCH_SIZE) {
    const chunkLen = queue[i].length | 0;
    if (batchBytes + chunkLen > BATCH_BYTES && batchCount > 0) break;
    batchBytes = batchBytes + chunkLen | 0;
    batchCount = batchCount + 1 | 0;
    i = i + 1 | 0;
  }

  const batch = queue.splice(0, batchCount);
  
  let payload;
  if (batch.length === 1) {
    payload = batch[0];
  } else {
    payload = new Uint8Array(batchBytes);
    let offset = 0;
    for (let j = 0; j < batch.length; j = j + 1 | 0) {
      payload.set(batch[j], offset);
      offset = offset + batch[j].length | 0;
    }
  }

  const self = this;
  this.writer.write(payload).then(
    () => {
      self.flushScheduled = false;
      if (self.queue.length > 0 && !self.state.closed) {
        self.scheduleFlush();
      }
    },
    () => self.state.shutdown()
  );
};

UplinkContext.prototype.push = function(chunk) {
  if (!this.state.closed) {
    this.queue.push(chunk);
    this.scheduleFlush();
  }
};

// ============ 上行管道 ============
function createUplink(state, initial, writable) {
  const writer = writable.getWriter();
  const ctx = new UplinkContext(state, writer);
  
  if (initial.length > 0) {
    ctx.push(initial);
  }

  return function onMessage(ev) {
    ctx.push(new Uint8Array(ev.data));
  };
}

// ============ 下行管道上下文（固定形状） ============
function DownlinkContext(state, ws, reader) {
  this.state = state;
  this.ws = ws;
  this.reader = reader;
  this.first = true;
  this.pending = null;
  this.pumping = false;
}

DownlinkContext.prototype.pump = function() {
  if (this.pumping || this.state.closed) return;
  this.pumping = true;
  
  const self = this;
  function step() {
    if (self.state.closed) {
      self.pumping = false;
      try { self.reader.releaseLock(); } catch {}
      return;
    }

    const buffered = self.ws.bufferedAmount | 0;
    if (buffered > WS_HIGH_WATER) {
      queueMicrotask(step);
      return;
    }

    const reading = self.pending || self.reader.read();
    self.pending = null;

    reading.then(
      (result) => {
        if (result.done || self.state.closed) {
          self.pumping = false;
          self.state.shutdown();
          try { self.reader.releaseLock(); } catch {}
          return;
        }

        self.pending = self.reader.read();

        const chunk = self.first ? buildFirstFrame(result.value) : result.value;
        self.first = false;
        self.ws.send(chunk);

        step();
      },
      () => {
        self.pumping = false;
        self.state.shutdown();
        try { self.reader.releaseLock(); } catch {}
      }
    );
  }

  step();
};

// ============ 下行管道 ============
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
  const cmdOffset = 18 + addonsLen | 0;

  if (cmdOffset + 3 > dataLen) return null;
  const cmd = data[cmdOffset] | 0;
  if ((cmd & 0xFE) !== 0) return null;

  const port = (data[cmdOffset + 1] << 8) | data[cmdOffset + 2];

  const addrOffset = cmdOffset + 3 | 0;
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
