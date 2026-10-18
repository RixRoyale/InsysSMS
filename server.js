const express = require('express');
const sql = require('mssql'); // Kept exclusively for Remote Sync
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const xlsx = require('xlsx');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({ storage: multer.memoryStorage() });

const JWT_SECRET = 'YOUR_SUPER_SECRET_KEY_REPLACE_THIS'; 
const CONFIG_FILE = path.join(process.cwd(), 'config.json');
const DB_FILE = path.join(process.cwd(), 'insys.db'); // Local SQLite Database

// Helper to open SQLite connection
async function getDb() {
    return open({
        filename: DB_FILE,
        driver: sqlite3.Database
    });
}

function getSavedConfig() {
    let defaultConfig = {
        remoteServer: '', remotePort: '', remoteDatabase: '',
        remoteUser: '', remotePassword: '', 
        lastSyncDocKey: 0
    };
    if (fs.existsSync(CONFIG_FILE)) {
        try { return { ...defaultConfig, ...JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8')) }; } 
        catch (err) { console.error('Error parsing config.json:', err); }
    }
    return defaultConfig;
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).send({ error: 'Access denied. No token provided.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send({ error: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
}

function checkPermission(featureKey) {
    return async (req, res, next) => {
        const role = req.user.role;
        if (role === 'Admin' || role === 'Administrator') return next();

        try {
            let db = await getDb();
            let result = await db.get(`SELECT COUNT(*) AS allowed FROM RolePermissions WHERE RoleName = ? AND FeatureKey = ?`, [role, featureKey]);

            if (result.allowed > 0) next();
            else res.status(403).send({ error: `Access Denied: Role '${role}' lacks '${featureKey}' permission.` });
        } catch (err) { res.status(500).send({ error: 'Failed to verify permission.' }); }
    };
}

function getFormattedDate(d) {
    const day = String(d.getDate()).padStart(2, '0');
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const month = months[d.getMonth()];
    const year = d.getFullYear();
    return `${day}/${month}/${year}`;
}

app.post('/api/setup', async (req, res) => {
    const { adminUserId, adminUserName, adminPhone, adminPassword, roles, adminRole } = req.body;
    
    if (!adminUserId || !adminUserName || !adminPassword || !roles || roles.length === 0 || !adminRole) {
        return res.status(400).send({ error: 'All fields are required.' });
    }

    try {
        let db = await getDb();

        await db.exec(`
            CREATE TABLE IF NOT EXISTS Roles (RoleName TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS RolePermissions (
                RoleName TEXT NOT NULL, FeatureKey TEXT NOT NULL,
                PRIMARY KEY (RoleName, FeatureKey),
                FOREIGN KEY (RoleName) REFERENCES Roles(RoleName) ON DELETE CASCADE ON UPDATE CASCADE
            );
            CREATE TABLE IF NOT EXISTS Users (
                UserKey INTEGER PRIMARY KEY AUTOINCREMENT, UserID TEXT UNIQUE NOT NULL, UserName TEXT NOT NULL,
                UserPhone TEXT NULL, PasswordHash TEXT NOT NULL, Role TEXT NOT NULL,
                UserActive TEXT DEFAULT 'T' CHECK (UserActive IN ('T', 'F'))
            );
            CREATE TABLE IF NOT EXISTS ServiceOrders (
                SOINumber TEXT PRIMARY KEY, IssueDate DATE NOT NULL, JunctionNo TEXT NOT NULL,
                Description TEXT NOT NULL, SONumber TEXT NULL, SODate DATE NULL, CreatedBy TEXT NULL,
                CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP, DocKey INTEGER NULL, PCNumber TEXT NULL, PCDate DATE NULL
            );
            CREATE TABLE IF NOT EXISTS acso (
                DocKey INTEGER PRIMARY KEY, DocNo TEXT NULL, DocDate DATE NULL, UDF_SOINO TEXT NULL,
                UDF_LOCATION TEXT NULL, UDF_EQUIP TEXT NULL, UDF_ATTBY TEXT NULL, UDF_ATTT TEXT NULL,
                UDF_PO TEXT NULL, SyncedAt DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        `);

        for (let r of roles) {
            await db.run(`INSERT OR IGNORE INTO Roles (RoleName) VALUES (?)`, [r]);
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(adminPassword, salt);

        let checkUser = await db.get('SELECT UserID FROM Users WHERE UserID = ?', [adminUserId]);
        if (!checkUser) {
            await db.run(`INSERT INTO Users (UserID, UserName, UserPhone, PasswordHash, Role, UserActive) VALUES (?, ?, ?, ?, ?, ?)`, 
                [adminUserId, adminUserName, adminPhone || '', hashedPassword, adminRole, 'T']);
        }

        res.status(200).send({ message: 'Setup complete!' });
    } catch (err) { res.status(500).send({ error: 'Setup failed: ' + err.message }); }
});

app.post('/api/login', async (req, res) => {
    const { userId, password } = req.body;
    try {
        let db = await getDb();
        let user = await db.get(`SELECT * FROM Users WHERE UserID = ?`, [userId]);
        
        if (!user) return res.status(401).send({ error: 'Invalid credentials.' });
        if (user.UserActive !== 'T') return res.status(403).send({ error: 'Account disabled.' });
        
        const isMatch = await bcrypt.compare(password, user.PasswordHash);
        if (!isMatch) return res.status(401).send({ error: 'Invalid credentials.' });

        let permResult = await db.all(`SELECT FeatureKey FROM RolePermissions WHERE RoleName = ?`, [user.Role]);
        const permissions = permResult.map(p => p.FeatureKey);
        
        const token = jwt.sign({ userKey: user.UserKey, userId: user.UserID, userName: user.UserName, role: user.Role }, JWT_SECRET, { expiresIn: '8h' });
        res.status(200).json({ token, role: user.Role, userName: user.UserName, userId: user.UserID, permissions });
    } catch (err) { res.status(500).send({ error: 'Internal server error.' }); }
});

app.get('/api/permissions/me', authenticateToken, async (req, res) => {
    try {
        let db = await getDb();
        let result = await db.all(`SELECT FeatureKey FROM RolePermissions WHERE RoleName = ?`, [req.user.role]);
        res.status(200).json(result.map(r => r.FeatureKey));
    } catch (err) { res.status(500).send({ error: 'Failed to fetch permissions.' }); }
});

app.get('/api/permissions/matrix', authenticateToken, checkPermission('ROLE_MGMT'), async (req, res) => {
    try {
        let db = await getDb();
        let result = await db.all(`SELECT RoleName, FeatureKey FROM RolePermissions`);
        res.status(200).json(result);
    } catch (err) { res.status(500).send({ error: 'Failed to fetch permission matrix.' }); }
});

app.post('/api/permissions/toggle', authenticateToken, checkPermission('ROLE_MGMT'), async (req, res) => {
    const { roleName, featureKey, enabled } = req.body;
    try {
        let db = await getDb();
        if (enabled) {
            await db.run(`INSERT OR IGNORE INTO RolePermissions (RoleName, FeatureKey) VALUES (?, ?)`, [roleName, featureKey]);
        } else {
            await db.run(`DELETE FROM RolePermissions WHERE RoleName = ? AND FeatureKey = ?`, [roleName, featureKey]);
        }
        res.status(200).send({ message: 'Permissions updated successfully.' });
    } catch (err) { res.status(500).send({ error: 'Failed to update permissions.' }); }
});

app.get('/api/outstanding-sois', authenticateToken, checkPermission('VIEW_SOIS'), async (req, res) => {
    try {
        let db = await getDb();
        let result = await db.all(`SELECT SOINumber, IssueDate, JunctionNo, Description, PCNumber, PCDate FROM ServiceOrders WHERE SONumber IS NULL ORDER BY IssueDate ASC`);
        res.status(200).json(result);
    } catch (err) { res.status(500).send({ error: 'Database query failed' }); }
});

app.post('/api/soi/import', authenticateToken, checkPermission('ADD_SOI'), upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).send({ error: 'No file uploaded.' });

    try {
        const workbook = xlsx.read(req.file.buffer, { type: 'buffer', cellDates: true });
        const sheetName = workbook.SheetNames[0];
        const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

        let db = await getDb();
        let imported = 0, skipped = 0;

        for (let row of data) {
            const soiNumber = row['SOI Number'] || row['SOINumber'] || row['UDF_SOINO'] || row['SOI_Number'];
            let issueDate = row['Issue Date'] || row['IssueDate'] || row['Date'] || row['DocDate'];
            const junctionNo = row['Junction No'] || row['JunctionNo'] || row['Location'] || row['UDF_LOCATION'];
            const description = row['Description'] || row['Details'] || 'Imported from Excel';
            const pcNumber = row['PC Number'] || row['PCNumber'] || null;
            let pcDateRaw = row['PC Date'] || row['PCDate'] || null;

            if (!soiNumber || !issueDate || !junctionNo) { skipped++; continue; }

            let finalDate = new Date(issueDate);
            if (isNaN(finalDate.getTime())) finalDate = new Date();
            let finalPcDate = pcDateRaw ? new Date(pcDateRaw) : null;

            let result = await db.run(`
                INSERT OR IGNORE INTO ServiceOrders (SOINumber, IssueDate, JunctionNo, Description, PCNumber, PCDate, CreatedBy)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [String(soiNumber).trim(), finalDate.toISOString(), String(junctionNo).trim(), String(description).trim(), pcNumber, finalPcDate ? finalPcDate.toISOString() : null, req.user.userName || req.user.userId]);

            if (result.changes > 0) imported++; else skipped++;
        }
        res.status(200).send({ message: `Import complete. Successfully added: ${imported}. Skipped (Duplicates/Errors): ${skipped}.` });
    } catch (err) { res.status(500).send({ error: 'Failed to process Excel file.' }); }
});

app.post('/api/remote-so-list', authenticateToken, checkPermission('VIEW_REMOTE_SO'), async (req, res) => {
    const { searchTerm } = req.body;
    const liveConfig = getSavedConfig();
    
    if (!liveConfig.remoteServer || !liveConfig.remoteDatabase || !liveConfig.remoteUser) {
        return res.status(400).send({ error: 'Remote Database connection details are not configured.' });
    }

    const remoteDbConfig = {
        user: liveConfig.remoteUser, password: liveConfig.remotePassword,
        server: liveConfig.remoteServer, port: parseInt(liveConfig.remotePort) || 1433,
        database: liveConfig.remoteDatabase,
        options: { encrypt: false, trustServerCertificate: true },
        connectionTimeout: 10000, requestTimeout: 15000
    };

    try {
        let remotePool = new sql.ConnectionPool(remoteDbConfig);
        await remotePool.connect();
        let remoteQuery = `
            SELECT UDF_SOINO, UDF_LOCATION, UDF_EQUIP, UDF_ATTBY, UDF_ATTT, UDF_PO, DocKey, DocNo, DocDate, UDF_PCNO
            FROM [${liveConfig.remoteDatabase}].[dbo].[SO] 
            WHERE UDF_LOCATION LIKE @searchTerm OR UDF_SOINO LIKE @searchTerm OR DocNo LIKE @searchTerm
            ORDER BY DocDate DESC
        `;
        let remoteResult = await remotePool.request().input('searchTerm', sql.VarChar, `%${searchTerm.trim()}%`).query(remoteQuery);
        await remotePool.close();
        res.status(200).json(remoteResult.recordset);
    } catch (err) { res.status(500).send({ error: 'Remote Search Failed: ' + err.message }); }
});

app.post('/api/sync-remote-soi', authenticateToken, checkPermission('VIEW_SOIS'), async (req, res) => {
    const liveConfig = getSavedConfig();
    if (!liveConfig.remoteServer || !liveConfig.remoteDatabase || !liveConfig.remoteUser) {
        return res.status(400).send({ error: 'Remote Database connection details are not configured.' });
    }

    let lastSyncDocKey = parseInt(liveConfig.lastSyncDocKey) || 0;
    const remoteDbConfig = {
        user: liveConfig.remoteUser, password: liveConfig.remotePassword,
        server: liveConfig.remoteServer, port: parseInt(liveConfig.remotePort) || 1433,
        database: liveConfig.remoteDatabase, options: { encrypt: false, trustServerCertificate: true },
        connectionTimeout: 10000, requestTimeout: 15000
    };

    try {
        let db = await getDb();
        let remotePool = new sql.ConnectionPool(remoteDbConfig);
        await remotePool.connect();
        let remoteQuery = `
            SELECT UDF_SOINO, UDF_LOCATION, UDF_EQUIP, UDF_ATTBY, UDF_ATTT, UDF_PO, DocKey, DocNo, DocDate
            FROM [${liveConfig.remoteDatabase}].[dbo].[SO] 
            WHERE DocKey > ${lastSyncDocKey} AND UDF_SOINO IS NOT NULL AND UDF_SOINO != ''
        `;
        let remoteResult = await remotePool.request().query(remoteQuery);
        await remotePool.close();

        if (remoteResult.recordset.length === 0) return res.status(200).send({ message: "No new remote SO records found to sync." });

        let updatedCount = 0, completedCount = 0, maxFetchedDocKey = lastSyncDocKey;

        for (let row of remoteResult.recordset) {
            if (row.DocKey && row.DocKey > maxFetchedDocKey) maxFetchedDocKey = row.DocKey;

            let combinedDesc = `Equipment: ${row.UDF_EQUIP || 'N/A'}\nProblem: ${row.UDF_PO || 'N/A'}\nAction: ${row.UDF_ATTT || 'N/A'}\nAttended By: ${row.UDF_ATTBY || 'N/A'}\nDocKey: ${row.DocKey || 'N/A'}`;
            
            let updateResult = await db.run(`
                UPDATE ServiceOrders SET JunctionNo = ?, Description = ?, SONumber = ?, SODate = ?, DocKey = ? WHERE SOINumber = ?
            `, [row.UDF_LOCATION || '', combinedDesc, row.DocNo || null, row.DocDate ? new Date(row.DocDate).toISOString() : null, row.DocKey || null, row.UDF_SOINO]);
            
            if (updateResult.changes > 0) {
                updatedCount++;
                if (row.DocNo) completedCount++;
            }

            if (row.DocKey) {
                await db.run(`
                    INSERT OR IGNORE INTO acso (DocKey, DocNo, DocDate, UDF_SOINO, UDF_LOCATION, UDF_EQUIP, UDF_ATTBY, UDF_ATTT, UDF_PO)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                `, [row.DocKey, row.DocNo || null, row.DocDate ? new Date(row.DocDate).toISOString() : null, row.UDF_SOINO, row.UDF_LOCATION, row.UDF_EQUIP, row.UDF_ATTBY, row.UDF_ATTT, row.UDF_PO]);
            }
        }

        liveConfig.lastSyncDocKey = maxFetchedDocKey;
        fs.writeFileSync(CONFIG_FILE, JSON.stringify(liveConfig, null, 4), 'utf-8');
        res.status(200).send({ message: `Synced ${updatedCount} records to local ACSO table. ${completedCount} SOIs completed and removed.` });
    } catch (err) { res.status(500).send({ error: 'Remote Sync Failed: ' + err.message }); }
});

app.post('/api/soi', authenticateToken, checkPermission('ADD_SOI'), async (req, res) => {
    const { soiNumber, issueDate, junctionNo, description, pcNumber, pcDate } = req.body;
    try {
        let db = await getDb();
        await db.run(`
            INSERT INTO ServiceOrders (SOINumber, IssueDate, JunctionNo, Description, PCNumber, PCDate, CreatedBy) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [soiNumber.trim(), new Date(issueDate).toISOString(), junctionNo.trim(), description.trim(), pcNumber ? pcNumber.trim() : null, pcDate ? new Date(pcDate).toISOString() : null, req.user.userName || req.user.userId]);
        res.status(201).send({ message: `Service Order ${soiNumber} created.` });
    } catch (err) { res.status(500).send({ error: 'Failed to create Service Order.' }); }
});

app.put('/api/soi/:soiNumber', authenticateToken, checkPermission('EDIT_SOI'), async (req, res) => {
    const { soiNumber } = req.params;
    const { issueDate, junctionNo, description, pcNumber, pcDate } = req.body;
    try {
        let db = await getDb();
        await db.run(`
            UPDATE ServiceOrders SET IssueDate = ?, JunctionNo = ?, Description = ?, PCNumber = ?, PCDate = ? WHERE SOINumber = ?
        `, [new Date(issueDate).toISOString(), junctionNo, description, pcNumber ? pcNumber.trim() : null, pcDate ? new Date(pcDate).toISOString() : null, soiNumber]);
        res.status(200).send({ message: `SOI '${soiNumber}' updated.` });
    } catch (err) { res.status(500).send({ error: 'Failed to update SOI.' }); }
});

app.delete('/api/soi/:soiNumber', authenticateToken, checkPermission('DELETE_SOI'), async (req, res) => {
    const { soiNumber } = req.params;
    try {
        let db = await getDb();
        let result = await db.run(`DELETE FROM ServiceOrders WHERE SOINumber = ?`, [soiNumber]);
        if (result.changes > 0) res.status(200).send({ message: `Service Order '${soiNumber}' deleted successfully.` });
        else res.status(404).send({ error: `SOI '${soiNumber}' not found.` });
    } catch (err) { res.status(500).send({ error: 'Failed to delete Service Order.' }); }
});

app.post('/api/register', authenticateToken, checkPermission('CREATE_USER'), async (req, res) => {
    const { userId, userName, userPhone, password, role, userActive } = req.body;
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        let db = await getDb();
        await db.run(`INSERT INTO Users (UserID, UserName, UserPhone, PasswordHash, Role, UserActive) VALUES (?, ?, ?, ?, ?, ?)`, 
            [userId, userName, userPhone || '', hashedPassword, role, userActive || 'T']);
        res.status(201).send({ message: 'User created successfully.' });
    } catch (err) { res.status(500).send({ error: 'Failed to create user.' }); }
});

app.get('/api/roles', authenticateToken, async (req, res) => {
    try {
        let db = await getDb();
        let result = await db.all(`SELECT RoleName FROM Roles ORDER BY RoleName ASC`);
        res.status(200).json(result.map(r => r.RoleName));
    } catch (err) { res.status(500).send({ error: 'Failed to fetch roles' }); }
});

app.get('/api/settings/database', authenticateToken, checkPermission('DB_SETTINGS'), (req, res) => {
    const liveConfig = getSavedConfig();
    res.status(200).json({ 
        remoteServer: liveConfig.remoteServer, remotePort: liveConfig.remotePort, 
        remoteDatabase: liveConfig.remoteDatabase, remoteUser: liveConfig.remoteUser 
    });
});

app.post('/api/settings/database', authenticateToken, checkPermission('DB_SETTINGS'), async (req, res) => {
    const { remoteServer, remotePort, remoteDatabase, remoteUser, remotePassword } = req.body;
    const liveConfig = getSavedConfig();
    const newConfig = { 
        ...liveConfig,
        remoteServer: remoteServer || liveConfig.remoteServer,
        remotePort: parseInt(remotePort) || liveConfig.remotePort,
        remoteDatabase: remoteDatabase || liveConfig.remoteDatabase,
        remoteUser: remoteUser || liveConfig.remoteUser,
        remotePassword: remotePassword || liveConfig.remotePassword,
    };

    fs.writeFileSync(CONFIG_FILE, JSON.stringify(newConfig, null, 4), 'utf-8');
    res.status(200).send({ message: 'Remote database settings saved successfully.' });
});

const PORT = 9090;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));