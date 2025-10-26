/**
 * @swagger
 * /api/customer/status/update:
 *   put:
 *     summary: Update customer status (IsDormant or IsLocked)
 *     description: Updates the status field (IsDormant or IsLocked) for a customer based on the provided account number.
 *     security:
 *       - basicAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               customerID:
 *                 type: string
 *                 description: CustomerID of the customer
 *                 default: ""
 *               fieldToUpdate:
 *                 type: string
 *                 enum: [IsDormant, IsLocked]
 *                 description: Field to update (IsDormant or IsLocked)
 *               newValue:
 *                 type: integer
 *                 enum: [0, 1]
 *                 description: New value for the field (0 or 1)
 *     responses:
 *       200:
 *         description: Customer status updated successfully
 *       400:
 *         description: Invalid field specified or value
 *       404:
 *         description: Customer not found
 *       500:
 *         description: Server error
 */

/**
 * @swagger
 * /api/customer/status/{customerID}:
 *   get:
 *     summary: Check customer subscription status
 *     description: Retrieves the status of the customer account, indicating whether it is locked, dormant, or requires a reset.
 *     security:
 *       - basicAuth: []
 *     parameters:
 *       - in: path
 *         name: customerID
 *         schema:
 *           type: string
 *         required: true
 *         description: CustomerID of the customer
 *         default: ""
 *     responses:
 *       200:
 *         description: Customer status retrieved successfully
 *       404:
 *         description: Customer not found
 *       500:
 *         description: Server error
 */


/**
 * @swagger
 * /api/customer/delete/{customerID}:
 *   delete:
 *     summary: Delete customer and corresponding PIN
 *     description: Deletes a customer service entry and its corresponding TIN based on the account number.
 *     security:
 *       - basicAuth: []
 *     parameters:
 *       - in: path
 *         name: customerID
 *         schema:
 *           type: string
 *         required: true
 *         description: CustomerID of the customer
 *         default: ""
 *     responses:
 *       200:
 *         description: Customer and TIN deleted successfully
 *       404:
 *         description: Customer not found
 *       500:
 *         description: Server error
 */

/**
 * @swagger
 * /api/customer/pin/{customerID}:
 *   get:
 *     summary: View customer's PIN
 *     description: Retrieves the customer’s TIN, decrypts it using an internal encryption key, and re-encrypts it using RSA for secure transmission. Returns the re-encrypted PIN and key details.
 *     security:
 *       - basicAuth: []
 *     parameters:
 *       - in: path
 *         name: customerID
 *         schema:
 *           type: string
 *         required: true
 *         description: CustomerID of the customer
 *         default: ""
 *     responses:
 *       200:
 *         description: Encrypted PIN and RSA encryption details provided
 *       404:
 *         description: Customer or TIN not found
 *       500:
 *         description: Server error
 */


/**
 * @swagger
 * /api/customer/pin/change:
 *   put:
 *     summary: Change customer PIN
 *     description: Changes the customer’s PIN after validating it meets format and complexity requirements, using RSA encryption for security.
 *     security:
 *       - basicAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               customerID:
 *                 type: string
 *                 description: CustomerID of the customer
 *                 default: ""
 *               encryptedPIN:
 *                 type: string
 *                 description: The new encrypted PIN
 *                 default: ""
 *               kid:
 *                 type: string
 *                 description: Key ID for retrieving the encryption key
 *                 default: ""
 *     responses:
 *       200:
 *         description: PIN updated successfully
 *       400:
 *         description: Bad request - New PIN is invalid or identical to the old PIN
 *       404:
 *         description: Customer or old PIN not found
 *       500:
 *         description: Internal server error
 */


/**
 * @swagger
 * /api/customer/subscribe:
 *   post:
 *     summary: Register a new customer
 *     description: Subscribes a customer with their account details and generates an initial PIN internally. Validates and encrypts the new PIN before storage.
 *     security:
 *       - basicAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               accountNumber:
 *                 type: string
 *                 description: Unique identifier for the customer
 *                 default: ""
 *               branchID:
 *                 type: string
 *                 description: Branch ID associated with the customer
 *                 default: ""
 *               country:
 *                 type: string
 *                 description: Country code or name of the customer
 *                 default: ""
 *               mobileNumber:
 *                 type: string
 *                 description: Customer's mobile phone number
 *                 default: ""
 *               encryptedPIN:
 *                 type: string
 *                 description: Initial encrypted PIN for the customer
 *                 default: ""
 *               kid:
 *                 type: string
 *                 description: Key ID for retrieving the encryption key
 *                 default: ""
 *     responses:
 *       200:
 *         description: Customer registered successfully
 *       400:
 *         description: Customer already exists or invalid data provided
 *       500:
 *         description: Server error
 */