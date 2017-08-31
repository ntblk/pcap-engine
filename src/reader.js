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

const fs = require('fs');
const assert = require('assert');
const _ = require('lodash');
const parseString = require('xml2js').parseString;

const pcap = require('./pcap-util');
const Formatter = require('./pipeline');

var fmt = new Formatter();
fmt.init_tshark();


var classify = new Formatter();
//classify.autoprint = true;
classify.init_rawshark(['ip.src', 'tcp.srcport', 'tcp.dstport', 'ip.dst']);

fmt.on('data', p => {
  //console.log(parseString(p));
  console.log(p);
});

// tshark -F pcap -w capture.pcap

function run() {
  var buf = fs.readFileSync('capture.pcap');

  var val;

  var magic_number = buf.readUInt32LE(0);
  var isLE = magic_number === 0xa1b2c3d4;
  // TODO: Support different endian byte orders.
  assert(isLE);

  const hdr_len = 24;

  var hdr = buf.slice(0, 24);
  fmt.write(hdr);

  var buf = buf.slice(24);

  var packets = pcap.splitPackets(buf);
  console.log(packets.length);

  _.each(packets, packet => {
    classify.query(packet.data).then(res => {
      console.log(res);
    });
  });

}

run();
