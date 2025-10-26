require('dotenv').config();
const express = require('express');
const sql = require('mssql'); // For database operations
const dbConfig = require('./config/dbconfig'); // Import the database configuration
const authConfig = require('./AuthConfig'); // Import the authentication configuration
const fs = require('fs');
const path = require('path');
const https = require('https');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const fetch = require('node-fetch'); // For making API requests
const forge = require('node-forge'); // For RSA encryption/decryption
const base64url = require('base64url'); // For Base64URL encoding/decoding
const logger = require('./logger');
const { encryptPin, decryptPin } = require('./pinEncryption');

const app = express();
app.use(express.json()); // Parse incoming JSON requests

// Helper (optional): fail fast if a required env var is missing
function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL;
const API_BASE_URL = requireEnv('API_BASE_URL');
const API_CLIENT_ID = requireEnv('API_CLIENT_ID');
const PIN_PASSPHRASE = process.env.PIN_PASSPHRASE;

// Swagger setup
const options = {
  definition: {
      openapi: '3.0.0',
      info: {
          title: 'Express API with Swagger',
          version: '1.0.0',
          description: 'API application',
      },
      servers: [
          {
              url: PUBLIC_BASE_URL,
              description: 'IVR',
          },
      ],
      components: {
          securitySchemes: {
              basicAuth: {
                  type: 'http',
                  scheme: 'basic',
              },
          },
      },
      security: [
          {
              basicAuth: [],
          },
      ],
  },
  apis: [path.join(__dirname, 'index.js'), path.join(__dirname, 'ArabBank_Helious.js')], // Use absolute paths
};



const swaggerSpec = swaggerJsdoc(options);
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ----- TLS certs from env paths -----
const HTTPS_KEY_PATH = requireEnv('HTTPS_KEY_PATH');
const HTTPS_CERT_PATH = requireEnv('HTTPS_CERT_PATH');
const GCP_CA_CERT_PATH = requireEnv('GCP_CA_CERT_PATH');

// Read the key and certificate from the C:\Certificat folder
const key = fs.readFileSync(HTTPS_KEY_PATH, 'utf8');
const cert = fs.readFileSync(HTTPS_CERT_PATH, 'utf8');

const httpsAgent = new https.Agent({
  ca: fs.readFileSync(GCP_CA_CERT_PATH), // trust the internal CA for outbound requests
});

// Create HTTPS server
const server = https.createServer({ key: key, cert: cert }, app);

// Basic Authentication Middleware
function basicAuth(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: 'Authentication required' });
    }

    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');

    logger.info(`[AUTH] Attempted login - Username: ${username}, Password: ${password}`);

    // Validate against the credentials from AuthConfig.js
    if (username === authConfig.username && password === authConfig.password) {
      logger.info(`[AUTH] ✅ Authentication successful for user: ${username}`);
        next();
    } else {
      logger.warn(`[AUTH] ❌ Invalid credentials - Username: ${username}`);
        return res.status(401).json({ message: 'Access denied. Invalid credentials' });
    }
}

// Helper function to validate PIN based on rules
function isValidPin(pin, oldPin) {
    // Check if PIN is exactly 4 digits
    if (!/^\d{4}$/.test(pin)) {
        return { valid: false, message: 'PIN must be exactly 4 digits.' };
    }

    // Check if PIN is different from the old PIN
    if (oldPin && pin === oldPin) {
        return { valid: false, message: 'New PIN must not be the same as the old PIN.' };
    }

    // Check for patterns and simple PINs
    const disallowedPins = ["1234", "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999"];
    if (disallowedPins.includes(pin)) {
        return { valid: false, message: 'PIN is too simple or follows a pattern.' };
    }

    return { valid: true, message: 'PIN is valid.' };
}

// Update IsDormant or IsLocked field for a customer based on specified value
app.put('/api/customer/status/update', basicAuth, async (req, res) => {
  const { customerID, fieldToUpdate, newValue } = req.body;
  logger.info(`[PUT] Received request to update customer status, customerID: ${customerID}, fieldToUpdate: ${fieldToUpdate}.`);

  // Validate the field to update and newValue
  if (!['IsDormant', 'IsLocked'].includes(fieldToUpdate)) {
      logger.warn(`Invalid field specified in update status: ${fieldToUpdate}`);
      return res.status(400).json({ message: 'Invalid field specified. Choose either IsDormant or IsLocked.' });
  }
  if (![0, 1].includes(newValue)) {
      logger.warn(`Invalid value specified in update status: ${newValue}`);
      return res.status(400).json({ message: 'Invalid value. Only 0 or 1 are allowed.' });
  }

  try {
      let pool = await sql.connect(dbConfig);

      // Retrieve the current value of the specified field
      const result = await pool.request()
          .input('customerID', sql.NVarChar, customerID)
          .query(`SELECT ${fieldToUpdate} FROM dbo.TIN_Customers WHERE CustomerID = @customerID`);

      if (result.recordset.length === 0) {
          logger.info(`Customer not found during status update, CustomerID: ${customerID}.`);
          return res.status(404).json({ message: 'Customer not found' });
      }

      // Convert true/false to 1/0 for comparison
      const currentValue = result.recordset[0][fieldToUpdate] ? 1 : 0;

      // Check if the current value is the same as the new value
      if (currentValue === newValue) {
          const statusMessage = newValue === 1
              ? `Account is already ${fieldToUpdate === 'IsLocked' ? 'locked' : 'dormant'}`
              : `Account is already ${fieldToUpdate === 'IsLocked' ? 'unlocked' : 'active'}`;
          logger.info(`${customerID} ${statusMessage}`);
          return res.json({ message: statusMessage });
      }

      // Build the update query
      let updateQuery;
      const reqPool = pool.request()
          .input('customerID', sql.NVarChar, customerID)
          .input('NewValue', sql.Bit, newValue);

      if (fieldToUpdate === 'IsLocked' && newValue === 0) {
          // Unlocking: reset LoginAttemptsCounter to 0
          updateQuery = `
              UPDATE dbo.TIN_Customers
              SET IsLocked = @NewValue,
                  LoginAttemptsCounter = 0,
                  LastModificationDate = GETDATE()
              WHERE CustomerID = @customerID
          `;
      } else {
          // Regular toggle of IsLocked or IsDormant
          updateQuery = `
              UPDATE dbo.TIN_Customers
              SET ${fieldToUpdate} = @NewValue,
                  LastModificationDate = GETDATE()
              WHERE CustomerID = @customerID
          `;
      }

      // Execute the update
      await reqPool.query(updateQuery);

      const successMessage = newValue === 1
          ? `Account has been successfully ${fieldToUpdate === 'IsLocked' ? 'locked' : 'set to dormant'}`
          : `Account has been successfully ${fieldToUpdate === 'IsLocked' ? 'unlocked and login attempts reset' : 'set to active'}`;
      logger.info(`${customerID} ${successMessage}`);
      return res.json({ message: successMessage });

  } catch (error) {
      logger.error(`Error updating status for ${customerID}: ${error.message}`);
      return res.status(500).json({ message: 'Server error', error: error.message });
  }
});


// API to check customer subscription status
app.get('/api/customer/status/:customerID', basicAuth, async (req, res) => {
  const { customerID } = req.params;
    logger.info(`[GET] Fetching status for CustomerID number: ${customerID}`);

    try {
        let pool = await sql.connect(dbConfig);

        // First query to get customer status
        const result = await pool.request()
            .input('CustomerID', sql.NVarChar, customerID)
            .query(`SELECT AccountNumber, IsLocked, IsDormant, IsRequiredReset 
                    FROM dbo.TIN_Customers 
                    WHERE CustomerID = @CustomerID`);

        let isMigrated = 0; // Default to not migrated
        // Check if the account number exists in the AccountPins table
        const migrationResult = await pool.request()
        .input('CustomerID', sql.NVarChar, customerID)
            .query(`SELECT 1 
                    FROM [AccountPins] 
                    WHERE AccountNumber = @CustomerID`);

        if (migrationResult.recordset.length > 0) {
            isMigrated = 1; // Account is migrated
        }

        if (result.recordset.length > 0) {
            const { IsLocked, IsDormant, IsRequiredReset } = result.recordset[0];
            let status = 'Active';
            if (IsLocked && IsDormant && IsRequiredReset) {
                status = 'Locked, Dormant, and Required to Reset';
            } else if (IsLocked && IsDormant) {
                status = 'Locked and Dormant';
            } else if (IsLocked && IsRequiredReset) {
                status = 'Locked and Required to Reset';
            } else if (IsDormant && IsRequiredReset) {
                status = 'Dormant and Required to Reset';
            } else if (IsLocked) {
                status = 'Locked';
            } else if (IsDormant) {
                status = 'Dormant';
            } else if (IsRequiredReset) {
                status = 'Required to Reset';
            }

            logger.info(`Customer status retrieved successfully for account number: ${customerID}`);
            return res.json({
                customerID,
                isLocked: IsLocked,
                isDormant: IsDormant,
                isRequiredReset: IsRequiredReset,
                status,
                isMigrated 
            });
        } else {
            logger.warn(`Customer not found for account number: ${customerID}`);
            return res.status(404).json({ message: 'Customer not found' });
        }
    } catch (error) {
        logger.error(`Failed to fetch customer status for account number: ${customerID}, Error: ${error.message}`);
        return res.status(500).json({ message: 'Server error' });
    }
});

// API to delete customer service and corresponding TIN
app.delete('/api/customer/delete/:customerID', basicAuth, async (req, res) => {
  const { customerID } = req.params;
  logger.info(`[DELETE] Request received to delete customer with CustomerID: ${customerID}`);

  try {
    const pool = await sql.connect(dbConfig);
    const transaction = new sql.Transaction(pool);
    await transaction.begin();

    try {
      // 1) Verify customer exists & grab numeric ID
      const customerResult = await transaction.request()
        .input('customerID', sql.NVarChar, customerID)
        .query(`
          SELECT ID
          FROM dbo.TIN_Customers
          WHERE CustomerID = @customerID
        `);

      if (customerResult.recordset.length === 0) {
        await transaction.rollback();
        return res.status(404).json({ message: 'Customer not found' });
      }
      const numericId = customerResult.recordset[0].ID;

      // 2) Delete from CustomersTINs (by numeric PK)
      await transaction.request()
        .input('CustomerId', sql.Int, numericId)
        .query(`
          DELETE FROM dbo.CustomersTINs
          WHERE CustomerID = @CustomerId
        `);

      // 3) Delete from AccountPins (harmless if no rows)
      await transaction.request()
        .input('customerID', sql.NVarChar, customerID)
        .query(`
          DELETE FROM dbo.AccountPins
          WHERE AccountNumber = @customerID
        `);

      // 4) Delete from TIN_Customers
      await transaction.request()
        .input('customerID', sql.NVarChar, customerID)
        .query(`
          DELETE FROM dbo.TIN_Customers
          WHERE CustomerID = @customerID
        `);

      await transaction.commit();
      logger.info(`Customer ${customerID} and all related data deleted.`);
      return res.json({ message: 'Customer deleted successfully' });

    } catch (err) {
      await transaction.rollback();
      logger.error(`Transaction error deleting customer ${customerID}: ${err.message}`);
      return res.status(500).json({ message: 'Error while deleting customer', error: err.message });
    }

  } catch (err) {
    logger.error(`DB connection/transaction error for ${customerID}: ${err.message}`);
    return res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// API to view customer's PIN
app.get('/api/customer/pin/:customerID', basicAuth, async (req, res) => {
    const { customerID } = req.params;
    logger.info(`[GET] Received request to View PIN for customerID number: ${customerID}`);
  
    try {
      let pool = await sql.connect(dbConfig);
  
      // First, validate if the customer exists in the main customer database
      const customerExistenceResult = await pool
        .request()
        .input('customerID', sql.NVarChar, customerID)
        .query(`SELECT ID FROM dbo.TIN_Customers WHERE CustomerID = @customerID`);
  
      if (customerExistenceResult.recordset.length === 0) {
        logger.warn(`Customer not found for account number: ${customerID}`);
        return res.status(404).json({ message: 'Customer not found' });
      }
  
      // Now, check if the encrypted PIN exists in the AccountPins table
      const pinResult = await pool
        .request()
        .input('customerID', sql.NVarChar, customerID)
        .query(`SELECT EncryptedPin FROM AccountPins WHERE AccountNumber = @customerID`);
  
      if (pinResult.recordset.length > 0) {
        const encryptedPinInDb = pinResult.recordset[0].EncryptedPin;
  
        // Decrypt the AES-encrypted PIN
        const plainPin = decryptPin(encryptedPinInDb, PIN_PASSPHRASE);
  
        // Generate Key Pair by calling the internal GCP RSA Key API
        const response = await fetch(
        `${API_BASE_URL}/digital-banking/ms/security/key-generator/v2/rsa/keys`,
          {
            method: 'POST',
            headers: {
              accept: 'application/json',
              'channel-name': 'IVR',
              'Content-Type': 'application/x-www-form-urlencoded',
              client_id: API_CLIENT_ID,
            },
            body: new URLSearchParams({
              country: 'JO',
              scope: 'Helios',
            }),
            agent: httpsAgent
          }
        );
  
        if (!response.ok) {
          logger.error(`Failed to generate key pair for Account: ${customerID}`);
          throw new Error('Failed to generate key pair');
        }
  
        const data = await response.json();
  
        const kid = data.data.kid;
        const n_b64 = data.data.n;
        const e_b64 = data.data.e;
  
        // Decode n and e from Base64URL
        const n_bytes = base64url.toBuffer(n_b64);
        const e_bytes = base64url.toBuffer(e_b64);
  
        const BigInteger = forge.jsbn.BigInteger;
  
        const n = new BigInteger(n_bytes.toString('hex'), 16);
        const e = new BigInteger(e_bytes.toString('hex'), 16);
  
        // Create the public key
        const publicKey = forge.pki.setRsaPublicKey(n, e);
  
        // Encrypt the *decrypted* PIN using the public key
        const encryptedPinForTransmission = publicKey.encrypt(
          plainPin,
          'RSAES-PKCS1-V1_5'
        );
  
        // Convert encrypted data to Base64URL string
        const encryptedPinBase64Url = base64url.fromBase64(
          forge.util.encode64(encryptedPinForTransmission)
        );
  
        logger.info(
          `PIN encrypted (via GCP public key) for transmission for customerID number: ${customerID}`
        );
        return res.json({
          customerID,
          encryptedPIN: encryptedPinBase64Url,
          kid: kid,
          isMigrated: 1,
        });
      } else {
        // Return response if encrypted PIN not found
        logger.warn(`Encrypted PIN not found for customerID number: ${customerID}`);
        return res.status(404).json({
          message: 'Encrypted PIN not found for the customer',
          isMigrated: 0,
        });
      }
    } catch (error) {
      logger.error(
        `Error handling request for customerID number: ${customerID}, Error: ${error.message}`
      );
      return res.status(500).json({ message: 'Server error',error: error.message });
    }
  });

  // Change Customer API
  app.put('/api/customer/pin/change', basicAuth, async (req, res) => {
    const { customerID, encryptedPIN, kid } = req.body;
    logger.info(`Received request to change PIN for CustomerID: ${customerID}`);
  
    // 1) Validate inputs
    if (!customerID || !encryptedPIN || !kid) {
      logger.error('Missing required fields in the request body');
      return res.status(400).json({ message: 'Missing required fields in the request body' });
    }
  
    try {
      const pool = await sql.connect(dbConfig);
  
      // 2) Ensure customer exists
      const customerResult = await pool.request()
        .input('customerID', sql.NVarChar, customerID)
        .query(`SELECT ID FROM dbo.TIN_Customers WHERE CustomerID = @customerID`);
      if (customerResult.recordset.length === 0) {
        logger.warn(`Customer not found for CustomerID: ${customerID}`);
        return res.status(404).json({ message: 'Customer not found' });
      }
  
      // 3) Fetch any existing encrypted PIN
      const oldPinResult = await pool.request()
        .input('customerID', sql.NVarChar, customerID)
        .query(`SELECT EncryptedPin FROM dbo.AccountPins WHERE AccountNumber = @customerID`);
  
      // 4) Retrieve RSA private key from GCP
      const rsaRes = await fetch(
        `${API_BASE_URL}/digital-banking/ms/security/key-generator/v2/rsa/keys/${kid}?country=JO&scope=helios`,
        {
          method: 'GET',
          headers: {
            accept: 'application/json',
            'channel-name': 'IVR',
            client_id: API_CLIENT_ID,
          },
          agent: httpsAgent
        }
      );
      if (!rsaRes.ok) {
        logger.error(`Failed to retrieve private key for CustomerID: ${customerID}`);
        throw new Error('Failed to retrieve private key');
      }
      const rsaData = (await rsaRes.json()).data;
      const n = new forge.jsbn.BigInteger(base64url.toBuffer(rsaData.n).toString('hex'), 16);
      const e = new forge.jsbn.BigInteger(base64url.toBuffer(rsaData.e).toString('hex'), 16);
      const d = new forge.jsbn.BigInteger(base64url.toBuffer(rsaData.d || '').toString('hex'), 16);
      const privateKey = d
        ? forge.pki.setRsaPrivateKey(n, e, d)      // for full key (change flow)
        : forge.pki.setRsaPublicKey(n, e);          // fallback if only public provided
  
      // 5) Decrypt the incoming new PIN
      const encryptedBuffer = forge.util.decode64(base64url.toBase64(encryptedPIN));
      const newPlainPIN = privateKey.decrypt(encryptedBuffer, 'RSAES-PKCS1-V1_5');
  
      // 6) If no old PIN exists, insert a new one
      if (oldPinResult.recordset.length === 0) {
        // Validate complexity (no old PIN to compare)
        const { valid, message } = isValidPin(newPlainPIN, null);
        if (!valid) {
          logger.warn(`Invalid new PIN format for CustomerID: ${customerID}`);
          return res.status(400).json({ message });
        }
        const encryptedNewPIN = encryptPin(newPlainPIN, PIN_PASSPHRASE);
        await pool.request()
          .input('customerID', sql.NVarChar, customerID)
          .input('EncryptedPin', sql.NVarChar, encryptedNewPIN)
          .input('CreatedAt', sql.DateTime, new Date())
          .query(`
            INSERT INTO dbo.AccountPins (AccountNumber, EncryptedPin, CreatedAt)
            VALUES (@customerID, @EncryptedPin, @CreatedAt)
          `);
        logger.info(`PIN created successfully for CustomerID: ${customerID}`);
        return res.json({ message: 'PIN created successfully' });
      }
  
      // 7) Existing PIN flow: decrypt old PIN
      const oldEncryptedPIN = oldPinResult.recordset[0].EncryptedPin;
      const oldPlainPIN = decryptPin(oldEncryptedPIN, PIN_PASSPHRASE);
  
      // 8) Prevent reuse of old PIN
      if (newPlainPIN === oldPlainPIN) {
        logger.info(`Attempt to reuse old PIN for CustomerID: ${customerID}`);
        return res.status(400).json({ message: 'New PIN must not be the same as the old PIN.' });
      }
  
      // 9) Validate new PIN complexity
      const { valid, message } = isValidPin(newPlainPIN, oldPlainPIN);
      if (!valid) {
        logger.warn(`Invalid new PIN format for CustomerID: ${customerID}`);
        return res.status(400).json({ message });
      }
  
      // 10) Encrypt and update
      const encryptedNewPIN = encryptPin(newPlainPIN, PIN_PASSPHRASE);
      const updateResult = await pool.request()
        .input('customerID', sql.NVarChar, customerID)
        .input('EncryptedPin', sql.NVarChar, encryptedNewPIN)
        .input('UpdatedAt', sql.DateTime, new Date())
        .query(`
          UPDATE dbo.AccountPins
          SET EncryptedPin = @EncryptedPin,
              UpdatedAt    = @UpdatedAt
          WHERE AccountNumber = @customerID
        `);
  
      if (updateResult.rowsAffected[0] > 0) {
        logger.info(`PIN updated successfully for CustomerID: ${customerID}`);
        return res.json({ message: 'PIN updated successfully' });
      } else {
        logger.error(`Failed to update PIN for CustomerID: ${customerID}`);
        return res.status(500).json({ message: 'Failed to update the PIN' });
      }
  
    } catch (error) {
      logger.error(`Error processing PIN change for CustomerID: ${customerID}: ${error.message}`);
      return res.status(500).json({ message: 'Server error', error: error.message });
    }
  });
  
// Subscribe Customer API
app.post('/api/customer/subscribe', basicAuth, async (req, res) => {
    const { accountNumber, branchID, country, mobileNumber, encryptedPIN, kid } = req.body;

        // Validation to ensure all fields have values
        if (!accountNumber || !branchID || !country || !mobileNumber || !encryptedPIN || !kid) {
          logger.error('Missing required fields in the request body');
          return res.status(400).json({ message: 'Missing required fields in the request body' });
      }
      
    const customerID = branchID + accountNumber;  // Concatenate branchID and accountNumber

    logger.info(`Attempting to register a new CustomerID with account number: ${customerID}`);
  
    try {
      let pool = await sql.connect(dbConfig);
  
      // Step 1: Check if the customer already exists
      const existingCustomer = await pool
        .request()
        .input('CustomerID', sql.NVarChar, customerID)
        .query(`SELECT ID FROM dbo.TIN_Customers WHERE CustomerID = @CustomerID`);
  
      if (existingCustomer.recordset.length > 0) {
        logger.warn(`Customer with CustomerID number ${customerID} already exists.`);
        return res
          .status(400)
          .json({ message: 'Customer already exists in the IVR system' });
      }
  
      // Step 2: Use KID to retrieve the private key from GCP
      const response = await fetch(
        `${API_BASE_URL}/digital-banking/ms/security/key-generator/v2/rsa/keys/${kid}?country=JO&scope=helios`,
        {
          method: 'GET',
          headers: {
            accept: 'application/json',
            'channel-name': 'IVR',
            client_id: API_CLIENT_ID,
          },
          agent: httpsAgent
        }
      );
  
      if (!response.ok) {
        logger.error(
          `Failed to retrieve private key for KID ${kid} during registration for CustomerID number: ${customerID}`
        );
        throw new Error('Failed to retrieve private key');
      }
  
      const data = await response.json();
  
      const n_b64 = data.data.n;
      const e_b64 = data.data.e;
      const d_b64 = data.data.d;
  
      // Decode n, e, d from Base64URL
      const n_bytes = base64url.toBuffer(n_b64);
      const e_bytes = base64url.toBuffer(e_b64);
      const d_bytes = base64url.toBuffer(d_b64);
  
      const BigInteger = forge.jsbn.BigInteger;
  
      const n = new BigInteger(n_bytes.toString('hex'), 16);
      const e = new BigInteger(e_bytes.toString('hex'), 16);
      const d = new BigInteger(d_bytes.toString('hex'), 16);
  
      // Create the private key
      const privateKey = forge.pki.setRsaPrivateKey(n, e, d);
  
      // Decrypt the encrypted PIN (from the request) using RSA
      const encryptedPINStr = forge.util.decode64(base64url.toBase64(encryptedPIN));
      const newPlainPIN = privateKey.decrypt(encryptedPINStr, 'RSAES-PKCS1-V1_5');
  
      // Step 3: Validate the new PIN
      const { valid, message } = isValidPin(newPlainPIN, null);
      if (!valid) {
        logger.warn(`Invalid new PIN format for CustomerID number: ${customerID}`);
        return res.status(400).json({ message });
      }
  
      // Step 4: Encrypt the PIN with AES before storing
      const encryptedPINForStorage = encryptPin(newPlainPIN, PIN_PASSPHRASE);
  
      // Step 5: Insert new customer into the TIN_Customers table
      const insertResult = await pool
        .request()
        .input('CustomerID', sql.NVarChar, customerID)
        .input('AccountNumber', sql.NVarChar, accountNumber)
        .input('BranchID', sql.NVarChar, branchID)
        .input('Country', sql.NVarChar, country)
        .input('MobileNumber', sql.NVarChar, mobileNumber)
        .input('IsDormant', sql.Bit, 0)
        .input('IsLocked', sql.Bit, 0)
        .input('IsRequiredReset', sql.Bit, 0)
        .input('CreationDate', sql.DateTime, new Date())
        .input('LastModificationDate', sql.DateTime, new Date()) // Set the current date
        .input('LastModifiedByID', sql.Int, 0)
        .input('LastModifiedByName', sql.NVarChar, 'null')
        .input('LoginAttemptsCounter', sql.Int, 0)
        .input('CreatedByID', sql.Int, 999)
        .input('CreatedByName', sql.NVarChar, 'ArabiMobile')
        .input('StatusID', sql.Int, 1)
        .input('CallID', sql.NVarChar, 'Mobile APP')
        .input('FaildSecurityQuestions', sql.Int, 0)
        .query(`
          INSERT INTO dbo.TIN_Customers (
            CustomerID, AccountNumber, BranchID, Country, MobileNumber, 
            IsDormant, IsLocked, IsRequiredReset, CreationDate, LastModificationDate,
            LastModifiedByID, LastModifiedByName, LoginAttemptsCounter, 
            CreatedByID, CreatedByName, StatusID, CallID, FaildSecurityQuestions
          ) 
          OUTPUT INSERTED.ID, INSERTED.LastModificationDate
          VALUES (
            @CustomerID, @AccountNumber, @BranchID, @Country, @MobileNumber,
            @IsDormant, @IsLocked, @IsRequiredReset, @CreationDate, @LastModificationDate,
            @LastModifiedByID, @LastModifiedByName, @LoginAttemptsCounter,
            @CreatedByID, @CreatedByName, @StatusID, @CallID, @FaildSecurityQuestions
          )
        `);
  
      // Step 6: Insert the encrypted PIN into the AccountPins table
      await pool
        .request()
        .input('AccountNumber', sql.NVarChar, customerID)
        .input('EncryptedPin', sql.NVarChar, encryptedPINForStorage)
        .input('CreatedAt', sql.DateTime, new Date())
        .query(`
          INSERT INTO dbo.AccountPins (AccountNumber, EncryptedPin, CreatedAt) 
          VALUES (@AccountNumber, @EncryptedPin, @CreatedAt)
        `);
  
      logger.info(`Customer successfully registered with CustomerID number: ${customerID}`);
      return res.json({
        message: 'Customer registered successfully',
      });
    } catch (error) {
      logger.error(
        `Error during customer registration for account number: ${accountNumber}: ${error.message}`
      );
      return res.status(500).json({ message: 'Server error', error: error.message });
    }
  });

// Start the server
const PORT = parseInt(process.env.PORT, 10) || 8091;
server.listen(PORT, () => {
    console.log(`HTTPS Server running on port ${PORT}`);
});
