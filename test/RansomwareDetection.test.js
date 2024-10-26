const RansomwareDetection = artifacts.require("RansomwareDetection");
const { expect } = require("chai");

contract("RansomwareDetection", accounts => {
  let detection;
  const owner = accounts[0];
  const reporter = accounts[1];
  
  beforeEach(async () => {
    detection = await RansomwareDetection.new({ from: owner });
  });
  
  it("should set the owner as trusted reporter", async () => {
    const isTrusted = await detection.trustedReporters(owner);
    expect(isTrusted).to.be.true;
  });
  
  it("should add trusted reporter", async () => {
    await detection.addTrustedReporter(reporter, { from: owner });
    const isTrusted = await detection.trustedReporters(reporter);
    expect(isTrusted).to.be.true;
  });
  
  it("should report detection", async () => {
    await detection.addTrustedReporter(reporter, { from: owner });
    const fileHash = "0x123456789";
    const timestamp = "2023-10-20 12:00:00";
    
    await detection.reportDetection(fileHash, timestamp, { from: reporter });
    const result = await detection.getDetection(fileHash);
    
    expect(result.fileHash).to.equal(fileHash);
    expect(result.timestamp).to.equal(timestamp);
    expect(result.reporter).to.equal(reporter);
    expect(result.isConfirmed).to.be.false;
  });
  
  it("should confirm detection", async () => {
    const fileHash = "0x123456789";
    const timestamp = "2023-10-20 12:00:00";
    
    await detection.reportDetection(fileHash, timestamp, { from: owner });
    await detection.confirmDetection(fileHash, { from: owner });
    
    const result = await detection.getDetection(fileHash);
    expect(result.isConfirmed).to.be.true;
  });
});