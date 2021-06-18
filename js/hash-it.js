// Code in this file from bip39 is under ISC
// Otherwise:
/*  
    Hash it!, a simple text (mis)representation encoder.
    Copyright 2021 Rhea Myers <rhea@hey.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
  Several different incompatible encoding are used here.
  For the UTF-8 encodings, note that there are no 0x00 values in the
  endoding, so nulls can be stripped during decoding.
  0. UTF-8 encoded as hex.
  1. UTF-8 padded at the end to the nearest 11 bits then encoded using the
     BIP-39 wordlist without a checksum appended. Decoding discards the
     trailing zero bits. This means that the last word will not directly
     represent the character value, but this is the least bad solution.
     The padding may append an extra null byte, decoding strips this.
  2. UTF-8 of <= 32 bytes, padded at the end to the nearest four bytes with
     a checksum added then encoded as per BIP-39. Decoding unpacks the
     value and strips trailing nulls.
  3. SHA-256 hash of 32 bytes encoded as hex.
  3. SHA-256 hash of 32 bytes with a checksum added and encoded and decoded
     as per BIP-39.
*/

const input = document.getElementById('input');
const hashIt = document.getElementById('go');
const copyToClipboard = document.getElementById('copy');
const output = document.getElementById('output');


function utf8ToHex(message) {
    return message
        .split('')
        .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join('');
}

// https://stackoverflow.com/a/48161723
async function utf8ToSha256(message) {
    // encode as UTF-8
    const msgBuffer = new TextEncoder().encode(message);                    

    // hash the message
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);

    // convert ArrayBuffer to Array
    return Array.from(new Uint8Array(hashBuffer));
}

function Sha256ToHex(raw) {
    return raw.map(b => (b.toString(16)).padStart(2, '0'))
        .join('');
}

function Sha256ToBip39(hex) {
    return bip39.entropyToMnemonic(hex);
}

function utf8ToBip39Words(text) {
    // Note that we zero pad the last few bits if needed.
    // We don't unpack this code, because we only use 11 here.
    const unpadded = text.split('')
          .map(a => a.charCodeAt(0))
          .map(a => a.toString(2).padStart(8, '0'))
          .join('');
    const padding = '0'.repeat(11 - (unpadded.length % 11));
    const bits = unpadded + padding;
    const wordlist = bip39.wordlists['EN'];
    const chunks = bits.match(/(.{1,11})/g);
    const words = chunks.map((binary) => {
        const index = parseInt(binary, 2);
        return wordlist[index];
    });
    return words.join(' ');
}

function bip39WordsToUtf8(mnemonic) {
    const wordlist = bip39.wordlists['EN'];
    const words = mnemonic.split(' ');
    const bits = words.map(word => {
        const index = wordlist.indexOf(word);
        return index.toString(2).padStart(11, '0');
    }).join('');
    // Note that 11-based padding means we may have an extra null byte at the end
    const bytes = bits.match(/.{8}/g)
          .map(b => parseInt(b, 2))
          .filter(b => b != 0);
    console.log(bytes);
    return new TextDecoder().decode(new Uint8Array(bytes));
}

function hexFromBip39(mnemonic) {
    return bip39.mnemonicToEntropy(mnemonic).toString('hex');
}

async function processInput(event) {
    const text = input.value;
    const utf8Bip39Words = utf8ToBip39Words(text);
    const sha256 = await utf8ToSha256(text);
    const sha256Hex = Sha256ToHex(sha256);
    const sha256Bip39 = Sha256ToBip39(sha256Hex);
    /*console.log(bip39WordsToUtf8(utf8Bip39Words));
    console.log(sha256);
    console.log(sha256Hex);
    console.log(hexFromBip39(sha256Bip39));*/
    output.innerHTML = '<h3>' + text + '</h3>'
        + '<dl><dt>UTF-8 Hex:</dt><dd>' + utf8ToHex(text) + '</dd>'
        + '<dt>UTF-8 BIP39 Words:</dt><dd>' + utf8Bip39Words +'</dd>'
        + '<dt>Sha256:</dt><dd>' + sha256Hex + '</dd>'
        + '<dt>Sha256 BIP39 (With Checksum):</dt><dd>' + sha256Bip39 + '</dd></dl>';
}

async function copyResultToClipboard() {
    const text = input.value;
    const utf8Bip39Words = utf8ToBip39Words(text);
    const sha256 = await utf8ToSha256(text);
    const sha256Hex = Sha256ToHex(sha256);
    const sha256Bip39 = Sha256ToBip39(sha256Hex);
    navigator.clipboard.writeText(`# ${text}
UTF-8 Hex:
     ${utf8ToHex(text)}
UTF-8 BIP39 Words:
     ${utf8Bip39Words}
Sha256:
     ${sha256Hex}
Sha256 BIP39 (With Checksum):
     ${sha256Bip39}`);
}

input.addEventListener('change', processInput);
hashIt.addEventListener('click', processInput);
copyToClipboard.addEventListener('click', copyResultToClipboard);
