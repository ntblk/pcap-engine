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

const EventEmitter = require('events');
const spawn = require('child_process').spawn;
const _ = require('lodash');
const byline = require('byline');

// cat capture.pcap | tshark -T pdml -r
// cat capture.pcap | tshark -T json -r -
// NOTE: tshark uses privileged dumpcap even when reading from stdin for -i but not -r. Why?

// TODO: Factor out functionality into separate classes or factory functions

class Formatter extends EventEmitter {
  init_dumpcap() {
    this.init('dumpcap', ['-q', '-P', '-w', '-']);
  }

  init_tshark(format) {
    this.init('tshark', ['-Q', '-l', '-T', format || 'pdml', '-i', '-']);
  }

  init_rawshark(fields) {
    var args = ['-l', '-n', '-d', 'encap:EN10MB', '-r', '-'];
    this.fields = _.map(fields, f => { return {name: f} });
    _.each(fields, f => { args.push('-F', f) });
    this.init('rawshark', args);
    this.expect((data) => {
      this.parseRawsharkHeader(data, this.fields);
    });
  }

  close() {
    this.ps.close();
  }

  expect(fn) {
    if (!this.waiters)
      this.waiters = [];
    this.waiters.push(fn);
  }

  init(cmd, args) {
    var ps = this.ps = spawn(cmd, args, {
      stdio: ['pipe', 'pipe', process.stderr],
      encoding: 'buffer',
    });

    ps.on('close', (code) => {
      if (code !== 0) {
        console.log(`ps process exited with code ${code}`);
      }
    });

    if (cmd === 'rawshark')
      this.output = byline.createStream(ps.stdout);
    else
      this.output = ps.stdout;

    this.output.on('data', (data) => {
      if (this.autoprint)
        console.log(data.toString('utf8'));
      if (this.waiters && this.waiters.length)
        this.waiters.shift()(data);
      else
        this.emit('data', data);
    });
  }

  write(data) {
    this.ps.stdin.write(data);
  }

  parseRawsharkHeader(line, fields) {
    // 0 FT_IPv4 BASE_NONE - 1 FT_UINT16 BASE_PT_TCP - 2 FT_UINT16 BASE_PT_TCP - 3 FT_IPv4 BASE_NONE -
    var res = {};
    var re = /(\d+) (\w+) (\w+) -/g;
    var m;
    while(m = re.exec(line)) {
      fields[m[1]].type = m[2];
      fields[m[1]].base = m[3];
    }
  }

  parseRawshark(line) {
    // NOTE: This skips some potentially useful info on the line.
    //var re = /^([\d]+) ((\d+)="([^"]+)" )+-$/g;
    var res = {};
    var re = /(\d+)="([^"]+)"/g;
    var m;
    while(m = re.exec(line)) {
      res[this.fields[m[1]].name] = m[2];
    }
    return res;
  }

  // FIXME: not right
  query(data) {
    return new Promise((resolve, reject) => {
      this.expect(res => {
        resolve(this.parseRawshark(res));
      });
      this.ps.stdin.write(data);
    });
  }
}

module.exports = Formatter;
