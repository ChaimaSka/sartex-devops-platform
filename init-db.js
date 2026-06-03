const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const db = new sqlite3.Database('./users.db');

async function initDatabase() {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            // Table users
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                role TEXT DEFAULT 'user',
                gitlab_token TEXT,
                jira_url TEXT,
                jira_email TEXT,
                jira_token TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`, (err) => { if (err) console.error('Erreur users:', err); else console.log('✅ Table users prête'); });

            // Table deployments
            db.run(`CREATE TABLE IF NOT EXISTS deployments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                project_name TEXT NOT NULL,
                language TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT,
                pipeline_url TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )`, (err) => { if (err) console.error('Erreur deployments:', err); else console.log('✅ Table deployments prête'); });

            // Table projects
            db.run(`CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                gitlab_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                language TEXT,
                is_favorite BOOLEAN DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, gitlab_id)
            )`, (err) => { if (err) console.error('Erreur projects:', err); else console.log('✅ Table projects prête'); });

            // Table settings (paramètres globaux)
            db.run(`CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )`, (err) => { if (err) console.error('Erreur settings:', err); else console.log('✅ Table settings prête'); });

            // Création du compte admin 
            db.get(`SELECT COUNT(*) as count FROM users`, async (err, row) => {
                if (err) return;
                if (row.count === 0) {
                    const hash = await bcrypt.hash('admin123', 10);
                    db.run(`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`,
                        ['admin', hash, 'admin']);
                    console.log('✅ Compte admin créé : admin / admin123');
                }
            });

            // Insertion d'une URL Jira par défaut dans settings
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`,
                ['jira_url', 'https://votre-instance.atlassian.net']);

            setTimeout(() => {
                db.close((err) => { if (err) reject(err); else resolve(); });
            }, 500);
        });
    });
}

initDatabase()
    .then(() => console.log('✅ Base de données initialisée avec succès.'))
    .catch(err => console.error('❌ Erreur fatale:', err));
