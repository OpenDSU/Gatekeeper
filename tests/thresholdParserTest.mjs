import utils from "./../Persisto/src/persistence/utils.js";
function testConfig(input,expected) {
    let result = utils.parseThresholds(input);
    //console.debug("Parsed input:", result);
    for(let i = 0; i < expected.length; i++) {
        if(result[i].threshold !== expected[i].threshold || result[i].value !== expected[i].value) {
            console.error("Test failed: ", result[i], expected[i]);
        } else {
            console.log("Test passed: ", result[i], expected[i]);
        }
    }
}

testConfig(["1:2"], [{threshold:1, value:2}]);
testConfig(["1:2","3:4"], [{threshold:1, value:2}, {threshold:3, value:4}]);
testConfig(["2048:10", "100000:5", "5000000:1", "1000000:0.1"], [{threshold:2048, value:10}, {threshold:100000, value:5}, {threshold:5000000, value:1}, {threshold:1000000, value:0.1}]);
testConfig(["2048:1", "100000:1", "5000000:0.2", "1000000:0.1"], [{threshold:2048, value:1}, {threshold:100000, value:1}, {threshold:5000000, value:0.2}, {threshold:1000000, value:0.1}]);
testConfig(["1:0.01", "10:0.02", "100:0.05", "1000:0.1", "10000:0.2", "100000:0.5", "1000000:1"], [{threshold:1, value:0.01}, {threshold:10, value:0.02}, {threshold:100, value:0.05}, {threshold:1000, value:0.1}, {threshold:10000, value:0.2}, {threshold:100000, value:0.5}, {threshold:1000000, value:1}]);
