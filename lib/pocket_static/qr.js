
const PorchQR = (function(){
  // QR Code Model 2, byte mode only, versions 1-40, error correction L/M/Q/H.
  // matrix(text, {ecl, mask, minVersion}) -> {size, version, mask, rows: [[bool]]}
  const ECC = {L:[-1,7,10,15,20,26,18,20,24,30,18,20,24,26,30,22,24,28,30,28,28,28,28,30,30,26,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],
               M:[-1,10,16,26,18,24,16,18,22,22,26,30,22,22,24,24,28,28,26,26,26,26,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28],
               Q:[-1,13,22,18,26,18,24,18,22,20,24,28,26,24,20,30,24,28,28,26,30,28,30,30,30,30,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],
               H:[-1,17,28,22,16,22,28,26,26,24,28,24,28,22,24,24,30,28,28,26,28,30,24,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30]};
  const BLOCKS = {L:[-1,1,1,1,1,1,2,2,2,2,4,4,4,4,4,6,6,6,6,7,8,8,9,9,10,12,12,12,13,14,15,16,17,18,19,19,20,21,22,24,25],
                  M:[-1,1,1,1,2,2,4,4,4,5,5,5,8,9,9,10,10,11,13,14,16,17,17,18,20,21,23,25,26,28,29,31,33,35,37,38,40,43,45,47,49],
                  Q:[-1,1,1,2,2,4,4,6,6,8,8,8,10,12,16,12,17,16,18,21,20,23,23,25,27,29,34,34,35,38,40,43,45,48,51,53,56,59,62,65,68],
                  H:[-1,1,1,2,4,4,4,5,6,8,8,11,11,16,16,18,16,19,21,25,25,25,34,30,32,35,37,40,42,45,48,51,54,57,60,63,66,70,74,77,81]};
  const FORMAT_ECL = {L:1, M:0, Q:3, H:2};
  function rawModules(v){
    let r = (16*v + 128)*v + 64;
    if(v >= 2){ const n = Math.floor(v/7) + 2; r -= (25*n - 10)*n - 55; if(v >= 7) r -= 36; }
    return r;
  }
  function dataCodewords(v, e){ return Math.floor(rawModules(v)/8) - ECC[e][v]*BLOCKS[e][v]; }
  function gmul(x, y){
    let z = 0;
    for(let i = 7; i >= 0; i--){ z = (z << 1) ^ ((z >>> 7) * 0x11D); z ^= ((y >>> i) & 1) * x; }
    return z & 0xFF;
  }
  function rsDivisor(n){
    const r = new Array(n).fill(0); r[n-1] = 1;
    let root = 1;
    for(let i = 0; i < n; i++){
      for(let j = 0; j < n; j++){ r[j] = gmul(r[j], root); if(j + 1 < n) r[j] ^= r[j+1]; }
      root = gmul(root, 2);
    }
    return r;
  }
  function rsRemainder(data, div){
    const r = new Array(div.length).fill(0);
    for(const b of data){
      const f = b ^ r.shift(); r.push(0);
      for(let i = 0; i < div.length; i++) r[i] ^= gmul(div[i], f);
    }
    return r;
  }
  function alignPositions(v){
    if(v === 1) return [];
    const n = Math.floor(v/7) + 2, size = v*4 + 17;
    const step = v === 32 ? 26 : Math.ceil((v*4 + 4)/(n*2 - 2))*2;
    const out = [6];
    for(let p = size - 7; out.length < n; p -= step) out.splice(1, 0, p);
    return out;
  }
  function matrix(text, opts){
    opts = opts || {};
    const ecl = opts.ecl || 'M';
    const bytes = Array.from(new TextEncoder().encode(text));
    let v = opts.minVersion || 1, cap;
    for(;; v++){
      if(v > 40) throw new Error('too long for a QR code');
      cap = dataCodewords(v, ecl) * 8;
      if(4 + (v <= 9 ? 8 : 16) + bytes.length*8 <= cap) break;
    }
    const bits = [];
    const put = (val, n) => { for(let i = n-1; i >= 0; i--) bits.push((val >>> i) & 1); };
    put(4, 4); put(bytes.length, v <= 9 ? 8 : 16);
    for(const b of bytes) put(b, 8);
    put(0, Math.min(4, cap - bits.length));
    put(0, (8 - bits.length % 8) % 8);
    for(let pad = 0xEC; bits.length < cap; pad ^= 0xEC ^ 0x11) put(pad, 8);
    const data = [];
    for(let i = 0; i < bits.length; i += 8){ let b = 0; for(let j = 0; j < 8; j++) b = (b << 1) | bits[i+j]; data.push(b); }
    // error correction blocks, interleaved
    const nb = BLOCKS[ecl][v], el = ECC[ecl][v], raw = Math.floor(rawModules(v)/8);
    const nShort = nb - raw % nb, shortLen = Math.floor(raw/nb);
    const div = rsDivisor(el), blocks = [];
    for(let i = 0, k = 0; i < nb; i++){
      const d = data.slice(k, k + shortLen - el + (i < nShort ? 0 : 1));
      k += d.length;
      const blk = d.concat(rsRemainder(d, div));
      if(i < nShort) blk.splice(shortLen - el, 0, -1);
      blocks.push(blk);
    }
    const cw = [];
    for(let i = 0; i < blocks[0].length; i++)
      for(let j = 0; j < nb; j++) if(blocks[j][i] !== -1) cw.push(blocks[j][i]);
    // function patterns
    const size = v*4 + 17;
    const m = [], fn = [];
    for(let y = 0; y < size; y++){ m.push(new Array(size).fill(false)); fn.push(new Array(size).fill(false)); }
    const set = (x, y, d) => { m[y][x] = !!d; fn[y][x] = true; };
    for(let i = 0; i < size; i++){ set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
    for(const [cx, cy] of [[3, 3], [size-4, 3], [3, size-4]])
      for(let dy = -4; dy <= 4; dy++) for(let dx = -4; dx <= 4; dx++){
        const x = cx + dx, y = cy + dy, d = Math.max(Math.abs(dx), Math.abs(dy));
        if(x >= 0 && x < size && y >= 0 && y < size) set(x, y, d !== 2 && d !== 4);
      }
    const al = alignPositions(v);
    for(let i = 0; i < al.length; i++) for(let j = 0; j < al.length; j++){
      if((i === 0 && j === 0) || (i === 0 && j === al.length-1) || (i === al.length-1 && j === 0)) continue;
      for(let dy = -2; dy <= 2; dy++) for(let dx = -2; dx <= 2; dx++)
        set(al[i] + dx, al[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
    function drawFormat(mask){
      const d = FORMAT_ECL[ecl] << 3 | mask;
      let r = d;
      for(let i = 0; i < 10; i++) r = (r << 1) ^ ((r >>> 9) * 0x537);
      const b = ((d << 10) | r) ^ 0x5412, bit = (i) => (b >>> i) & 1;
      for(let i = 0; i <= 5; i++) set(8, i, bit(i));
      set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8));
      for(let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
      for(let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
      for(let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
      set(8, size - 8, 1);
    }
    drawFormat(0);
    if(v >= 7){
      let r = v;
      for(let i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1F25);
      const b = v << 12 | r;
      for(let i = 0; i < 18; i++){
        const bit = (b >>> i) & 1, a = size - 11 + i % 3, c = Math.floor(i/3);
        set(a, c, bit); set(c, a, bit);
      }
    }
    // codewords, zigzag from the bottom right
    let i = 0;
    for(let right = size - 1; right >= 1; right -= 2){
      if(right === 6) right = 5;
      for(let vert = 0; vert < size; vert++) for(let j = 0; j < 2; j++){
        const x = right - j, up = ((right + 1) & 2) === 0, y = up ? size - 1 - vert : vert;
        if(!fn[y][x] && i < cw.length*8){ m[y][x] = ((cw[i >>> 3] >>> (7 - (i & 7))) & 1) === 1; i++; }
      }
    }
    const MASKS = [(x,y)=>(x+y)%2===0, (x,y)=>y%2===0, (x,y)=>x%3===0, (x,y)=>(x+y)%3===0,
      (x,y)=>(Math.floor(x/3)+Math.floor(y/2))%2===0, (x,y)=>x*y%2+x*y%3===0,
      (x,y)=>(x*y%2+x*y%3)%2===0, (x,y)=>((x+y)%2+x*y%3)%2===0];
    function applyMask(k){
      for(let y = 0; y < size; y++) for(let x = 0; x < size; x++) if(!fn[y][x] && MASKS[k](x, y)) m[y][x] = !m[y][x];
    }
    function penalty(){
      let p = 0, dark = 0;
      for(let a = 0; a < 2; a++) for(let y = 0; y < size; y++){
        let run = 1;
        const at = (k) => a ? m[k][y] : m[y][k];
        for(let x = 1; x <= size; x++){
          if(x < size && at(x) === at(x-1)) run++;
          else { if(run >= 5) p += run - 2; run = 1; }
        }
        for(let x = 0; x + 7 <= size; x++){
          const s = [1,0,1,1,1,0,1].every((want, k) => at(x+k) === !!want);
          if(!s) continue;
          const light = (from, to) => { for(let k = from; k < to; k++) if(k >= 0 && k < size && at(k)) return false; return true; };
          if(light(x-4, x) || light(x+7, x+11)) p += 40;
        }
      }
      for(let y = 0; y + 1 < size; y++) for(let x = 0; x + 1 < size; x++){
        const c = m[y][x];
        if(c === m[y][x+1] && c === m[y+1][x] && c === m[y+1][x+1]) p += 3;
      }
      for(const row of m) for(const c of row) if(c) dark++;
      p += Math.floor(Math.abs(dark*20 - size*size*10) / (size*size)) * 10;
      return p;
    }
    let mask = opts.mask;
    if(mask === undefined){
      let best = Infinity;
      for(let k = 0; k < 8; k++){
        applyMask(k); drawFormat(k);
        const p = penalty();
        if(p < best){ best = p; mask = k; }
        applyMask(k);
      }
    }
    applyMask(mask); drawFormat(mask);
    return {size, version: v, mask, rows: m};
  }
  // An <svg> of the matrix (one path, 4-module quiet zone), classes only.
  function svg(text, opts){
    const q = matrix(text, opts), n = q.size + 8, NS = 'http://www.w3.org/2000/svg';
    const s = document.createElementNS(NS, 'svg');
    s.setAttribute('viewBox', '0 0 ' + n + ' ' + n);
    s.setAttribute('class', 'qr');
    s.setAttribute('role', 'img');
    s.setAttribute('shape-rendering', 'crispEdges');
    const bg = document.createElementNS(NS, 'rect');
    bg.setAttribute('width', n); bg.setAttribute('height', n); bg.setAttribute('class', 'qr-light');
    let d = '';
    for(let y = 0; y < q.size; y++) for(let x = 0; x < q.size; x++)
      if(q.rows[y][x]) d += 'M' + (x+4) + ' ' + (y+4) + 'h1v1h-1z';
    const p = document.createElementNS(NS, 'path');
    p.setAttribute('d', d); p.setAttribute('class', 'qr-dark');
    s.append(bg, p);
    return s;
  }
  return {matrix, svg};
})();
