import utils from "../Persisto/src/persistence/utils.js";
import assert from 'assert';
function testNumber(number, prefix) {
    let longName = utils.transformToAccountID(number, prefix);
    let shortId = utils.getShortName(longName, prefix);
    let reconstructedLongName = utils.getFullName(shortId, prefix);
    console.log("Testing: ", number, shortId, longName, reconstructedLongName);
    assert(longName === reconstructedLongName);
}

testNumber(1, "U");
testNumber(10, "U");
testNumber(35, "U");
testNumber(36, "U");
testNumber(37, "U");

testNumber(36 * 10, "A");
testNumber(36 * 100, "A");
testNumber(36 * 100, "A");
testNumber(36 * 1000, "A");
testNumber(36 * 10000, "A");
testNumber(36 * 100000, "A");
testNumber(36 * 1000000, "A");
testNumber(36 * 1000000 + 1, "A");
