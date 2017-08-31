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

const assert = require('assert');
const _ = require('lodash');
const Formatter = require('./pipeline');
const pcap = require('./pcap-util');

const QUEUE_TTL = 60*1000;

class Session {
  start(cb) {
    this.queue = [];

    var classifier = new Formatter();
    classifier.init_rawshark(['ip.src', 'tcp.srcport', 'tcp.dstport', 'ip.dst']);

    var cap = new Formatter();
    cap.expect((buf) => {
      assert(buf.length === 24);
      var magic_number = buf.readUInt32LE(0);
      var isLE = magic_number === 0xa1b2c3d4;
      // TODO: Support different endian byte orders.
      assert(isLE);
      this.headerData = buf;
      if (cb)
        cb();
    });
    cap.init_dumpcap();

    cap.on('data', data => {
      // TODO: Do splitting in the pcap class instead of here?
      _.each(pcap.splitPackets(data), p => cap.emit('packet', p));
      //this.queue.splice(0, Math.max(0, this.queue.length - QUEUE_LENGTH));
    });

    cap.on('packet', packet => {
      // TODO: We could classify lazily when needed as an optimization.
      classifier.query(packet).then(fields => {
        var info = {
          fields,
          timestamp: pcap.parseTimestamp(packet),
          data: packet,
        };
        this.queue.push(info);
        this.triggerPrune();
      });
    });
  }

  // Avoids interval when queue is empty or not in use.
  // TODO: Clear timer on close?
  triggerPrune() {
    if (this.interval)
      return;
    this.interval = setInterval(() => {
      this.prune();
      if (this.queue.length)
        return;
      clearTimeout(this.interval);
      this.interval = null;
    }, QUEUE_TTL);
  }

  prune() {
    var cutoff = new Date(Date.now() - QUEUE_TTL);
    var i = _.sortedIndexBy(this.queue, {timestamp: cutoff}, 'timestamp');
    //console.log(i);
    if (i > 0)
      this.queue.splice(0, i);
  }

  serialize(ostream, test) {
    ostream.write(this.headerData);
    _(this.queue).filter(test).each(info => {
      ostream.write(info.data);
    });
  }
}

module.exports = Session;
