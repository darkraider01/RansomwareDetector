const RansomwareDetection = artifacts.require("RansomwareDetection");

module.exports = function (deployer) {
    deployer.deploy(RansomwareDetection, { gas: 6500000 });
};
