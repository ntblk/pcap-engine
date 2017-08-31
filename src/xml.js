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
const xml2js = require('xml2js');

// TODO: See JS coloring for UX at /usr/share/wireshark/pdml2html.xsl
// TODO: See node-tshark for possible non-XML implementation
// TODO: Can we extract the range info in a more flat non-XML format?

// https://stackoverflow.com/questions/40937961/lodash-keyby-for-multiple-nested-level-arrays
function deepKeyBy(arr, key) {
  if (_.isPlainObject(arr))
    return _.map(arr, v => deepKeyBy(v, key));
  if (_.isArray(arr))
    return _(arr)
      .map(function(o) {
        return _.mapValues(o, function(v) {
          return deepKeyBy(v, key);
        });
      })
      .keyBy(key);
  return arr;
}

function transformXML (str) {
  xml2js.parseString(str, {
    mergeAttrs: true,
    // TODO: explicitArray could break schema?
    explicitArray: false,
    //attrValueProcessors: {parseNumbers: true,},
  }, (err, res) => {
    assert(!err);
    res.packet = deepKeyBy(res.packet, 'name');
    //res.packet.proto = deepKeyBy(res.packet.proto, 'name');
    console.log(JSON.stringify(res, null, 2));
  });
}

var str = fs.readFileSync('packet.xml');
transformXML(str);

module.exports.transformXML = transformXML;
