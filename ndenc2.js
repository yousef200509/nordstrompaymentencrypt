const forge = require('node-forge');

function aH() {}

function bc(br) {
    var bk = 0;
    var bi;
    var bv;
    var bu;
    var bp;
    var bq;
    try {
        bu = sjcl.random.randomWords((br.length / 4) + 1, 0);
        var bn = 0;
        while (bk < bu.length) {
            var bl = bu[bk++];
            var bs = bl >> 0 & 255;
            var bt = bl >> 8 & 255;
            var bh = bl >> 16 & 255;
            var bm = bl >> 24 & 255;
            while (bs == 0 || bt == 0 || bh == 0 || bm == 0) {
                bq = new Array();
                bq = sjcl.random.randomWords(1, 0);
                bl = bq[0];
                bs = bl >> 0 & 255;
                bt = bl >> 8 & 255;
                bh = bl >> 16 & 255;
                bm = bl >> 24 & 255
            }
            if (bn < br.length) {
                br[bn++] = bs
                    }
            if (bn < br.length) {
                br[bn++] = bt
                    }
            if (bn < br.length) {
                br[bn++] = bh
                    }
            if (bn < br.length) {
                br[bn++] = bm
                    }
        }
    } catch (bo) {
        for (bv = 0; bv < br.length; ++bv) {
            var bj = Math.floor((Math.random() * 255) + 1);
            while (bj == 0) {
                bj = Math.floor((Math.random() * 255) + 1)
            }
            br[bk++] = bj
        }
    }
    return 1
}
aH.prototype.nextBytes = bc;

function aN(bk, bn) {
    if (bn < bk.length + 11) {
        throw "Message too long for RSA"
    }
    var bm = new Array();
    var bj = bk.length - 1;
    while (bj >= 0 && bn > 0) {
        var bl = bk.charCodeAt(bj--);
        if (bl < 128) {
            bm[--bn] = bl
        } else {
            if ((bl > 127) && (bl < 2048)) {
                bm[--bn] = (bl & 63) | 128;
                bm[--bn] = (bl >> 6) | 192
            } else {
                bm[--bn] = (bl & 63) | 128;
                bm[--bn] = ((bl >> 6) & 63) | 128;
                bm[--bn] = (bl >> 12) | 224
            }
        }
    }
    bm[--bn] = 0;
    var bi = new aH();
    var bh = new Array(bn - 2);
    bi.nextBytes(bh);
    bj = 0;
    while (bn > 2) {
        bm[--bn] = bh[bj];
        bj++
    }
    bm[--bn] = 2;
    bm[--bn] = 0;
    return new forge.jsbn.BigInteger(bm)
}

function x() {
    this.n = null;
    this.e = 0;
    this.d = null;
    this.p = null;
    this.q = null;
    this.dmp1 = null;
    this.dmq1 = null;
    this.coeff = null
}

function h(bi, bh) {
    return new forge.jsbn.BigInteger(bi,bh)
}

function s(bi, bh) {
    if (bi != null && bh != null && bi.length > 0 && bh.length > 0) {
        this.n = h(bi, 16);
        this.e = parseInt(bh, 16)
    } else {
        throw "Error setting public key"
    }
}


function av(bh) {
    return bh.modPowInt(this.e, this.n)
}

function u(bj) {
    var bh = aN(bj, (this.n.bitLength() + 7) >> 3);
    if (bh == null) {
        return null
    }
    var bk = this.doPublic(bh);
    if (bk == null) {
        return null
    }
    var bi = bk.toString(16);
    if ((bi.length & 1) == 0) {
        return bi
    } else {
        return "0" + bi
    }
}

x.prototype.doPublic = av;
x.prototype.setPublic = s;
x.prototype.encrypt = u;

const aB = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const at = "=";

function aI(bj) {
    var bi;
    var bk;
    var bh = "";
    for (bi = 0; bi + 3 <= bj.length; bi += 3) {
        bk = parseInt(bj.substring(bi, bi + 3), 16);
        bh += aB.charAt(bk >> 6) + aB.charAt(bk & 63)
    }
    if (bi + 1 == bj.length) {
        bk = parseInt(bj.substring(bi, bi + 1), 16);
        bh += aB.charAt(bk << 2)
    } else {
        if (bi + 2 == bj.length) {
            bk = parseInt(bj.substring(bi, bi + 2), 16);
            bh += aB.charAt(bk >> 2) + aB.charAt((bk & 3) << 4)
        }
    }
    while ((bh.length & 3) > 0) {
        bh += at
    }
    return bh
}



const b = {
    modulus: "a98a8539a9566bffd6ee5a85e36a020c326ba0801519b5f3b77949236c9249f7fd830154310c6685d35c92b0bcbd5f3c6a11667c056885e271ab3a39585425ede7e840589f0189f5d0df15aa80ad19917d5734d19dedc333ca4d476bf53773d7091f592ec6426e3813774b3410b91d2e7c474dbc869f1d7c3d8cc6b97077a6204d90f1dcd98c6545263f49d8760d5d953ff86ee2dfad6caca5f88747426ecd21de2b34249b523526c8ba26c0995a7158bd74a5c68e75f1ed0c5677963b0e5e5b12a1b4334aadec18e0ad3d333c8c4302fae55afcdf1f937af51e2c6ef95d842d5aee147470ffcf573fe4fe0040c06ba394844aeaa0ab91509cbf9d283783d30d",
    exponent: "10001",
    keyId: "27262900049",
    visaCheckoutApiKey: "YIVDE0GZEE18VM6BFYIS218dbXdWD-42bCYl0m0KPUxgix_qE",
    visaCheckoutEncryptionKey: "GOR4DEIB9H0A0FYVZQJC14N4-6kbAF8FZi58EWWIMcv0IkSPQ"
};

function encryptInfo(value) {
    let encryptObject = new x();
    let pubKey = encryptObject.setPublic(b.modulus, b.exponent);
    let encryptedInfo = encryptObject.encrypt(value)
    encryptedInfo = aI(encryptedInfo);
    encryptedInfo = encodeURIComponent(encryptedInfo) 
    return encryptedInfo
}

module.exports = encryptInfo