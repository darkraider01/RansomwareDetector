module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",     // Localhost (default: none)
      port: 7545,            // Standard Ethereum port (default: none)
      network_id: "5777", 
      gas: 6500000,         // Set below block limit
      gasPrice: 20000000000 // Optional: Set a lower gas price if needed
    },
  },

  mocha: {
    // timeout: 100000
  },

  compilers: {
    solc: {
      version: "0.8.0",
      settings: { optimizer: { enabled: false, runs: 200 } }
    }
  }
  
};
