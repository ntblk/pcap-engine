// Copyright (c) 2017 NetBlocks Project <https://netblocks.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

const _ = require('lodash');

var proto = Buffer.prototype;
//console.log(proto);

// .filter(k => /^read/.test(k)).value()
//var readers = _(proto).keysIn().value();
//console.log(readers);

//console.log(_.filter(proto, p => true));

//console.log(_.keys(proto));

var re = /^([a-z]+)(.+)(LE|BE)$/;

var eprops = {};

for (key in proto) {
  var m = key.match(re);
  if (!m)
    continue;
  var fn = proto[key];
  var op = m[1], type = m[2], order = m[3];
  if (order === 'LE')
    eprops[op+type] = fn;
  console.log(m);
  //console.log(key);
}


Object.spawn = function (parent, props) {
  var defs = {}, key;
  for (key in props) {
    if (props.hasOwnProperty(key)) {
      defs[key] = {value: props[key], enumerable: true};
    }
  }
  return Object.create(parent, defs);
}


const fs = require('fs');
const assert = require('assert');

// tshark -F pcap -w capture.pcap

var buf = fs.readFileSync('capture.pcap');

buf = Object.spawn(buf, eprops);

var magic_number = buf.readUInt32(0);
console.log(magic_number);
