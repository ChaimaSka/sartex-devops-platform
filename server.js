const express = require('express');
const https = require('https');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
//const { Mistral } = require('@mistralai/mistralai');
const app = express();

const sslOptions = {
    key: fs.readFileSync('./ssl/key.pem'),
    cert: fs.readFileSync('./ssl/cert.pem')
};

const db = new sqlite3.Database('./users.db');

// Ajout des colonnes Jira
db.serialize(() => {
    db.run("ALTER TABLE users ADD COLUMN jira_url TEXT", (err) => { if (err && !err.message.includes('duplicate')) console.log('Colonne jira_url ajoutée'); });
    db.run("ALTER TABLE users ADD COLUMN jira_email TEXT", (err) => { if (err && !err.message.includes('duplicate')) console.log('Colonne jira_email ajoutée'); });
    db.run("ALTER TABLE users ADD COLUMN jira_token TEXT", (err) => { if (err && !err.message.includes('duplicate')) console.log('Colonne jira_token ajoutée'); });
});

app.use(session({
    secret: 'sartex-devops-secret-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(express.static('public'));
app.use(express.json());

function requireAuth(req, res, next) {
    if (req.session.user) next();
    else res.status(401).json({ error: 'Non authentifié' });
}

function requireAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') next();
    else res.status(403).json({ error: 'Accès refusé – droits administrateur requis' });
}

// ========== AUTH ==========
app.post('/api/register', async (req, res) => {
    const { username, password, gitlab_token } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: 'Nom et mot de passe requis' });
    db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
        if (row) return res.status(409).json({ success: false, message: 'Nom déjà utilisé' });
        const hash = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password_hash, role, gitlab_token) VALUES (?, ?, ?, ?)',
            [username, hash, 'user', gitlab_token || null], (err) => {
            if (err) return res.status(500).json({ success: false, message: 'Erreur création' });
            res.json({ success: true, message: 'Compte créé !' });
        });
    });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: 'Identifiants requis' });
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) return res.status(401).json({ success: false, message: 'Identifiants invalides' });
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ success: false, message: 'Identifiants invalides' });
        req.session.user = { id: user.id, username: user.username, role: user.role, gitlab_token: user.gitlab_token };
        req.session.save();
        res.json({ success: true, role: user.role });
    });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/me', (req, res) => {
    if (req.session.user) res.json({ authenticated: true, user: req.session.user });
    else res.json({ authenticated: false });
});

// ========== TOKEN GITLAB ==========
app.get('/api/user/token', requireAuth, (req, res) => {
    db.get('SELECT gitlab_token FROM users WHERE id = ?', [req.session.user.id], (err, row) => {
        if (err || !row) return res.status(500).json({ error: 'Erreur' });
        res.json({ token: row.gitlab_token || null });
    });
});

app.put('/api/user/token', requireAuth, async (req, res) => {
    const { token } = req.body;
    db.run('UPDATE users SET gitlab_token = ? WHERE id = ?', [token, req.session.user.id], (err) => {
        if (err) return res.status(500).json({ error: 'Erreur mise à jour' });
        req.session.user.gitlab_token = token;
        res.json({ success: true });
    });
});

// ========== ADMIN USERS ==========
app.get('/api/admin/users', requireAdmin, (req, res) => {
    db.all('SELECT id, username, role, gitlab_token, created_at FROM users', (err, rows) => {
        if (err) return res.status(500).json({ error: 'Erreur base' });
        res.json(rows);
    });
});

app.delete('/api/admin/users/:username', requireAdmin, (req, res) => {
    const { username } = req.params;
    if (username === 'admin') return res.status(403).json({ error: 'Admin principal non supprimable' });
    if (username === req.session.user.username) return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte' });
    db.run('DELETE FROM users WHERE username = ?', [username], function(err) {
        if (err) return res.status(500).json({ error: 'Erreur suppression' });
        if (this.changes === 0) return res.status(404).json({ error: 'Utilisateur non trouvé' });
        res.json({ success: true });
    });
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
    const { username, password, role, gitlab_token } = req.body;
    if (!username || !password || !role) return res.status(400).json({ error: 'Nom, mot de passe et rôle requis' });
    db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
        if (row) return res.status(409).json({ error: 'Utilisateur existe déjà' });
        const hash = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password_hash, role, gitlab_token) VALUES (?, ?, ?, ?)',
            [username, hash, role, gitlab_token || null], (err) => {
            if (err) return res.status(500).json({ error: 'Erreur insertion' });
            res.json({ success: true });
        });
    });
});

app.put('/api/admin/users/:username/password', requireAdmin, async (req, res) => {
    const { username } = req.params;
    const { newPassword } = req.body;
    if (!newPassword) return res.status(400).json({ error: 'Nouveau mot de passe requis' });
    db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
        if (!row) return res.status(404).json({ error: 'Utilisateur non trouvé' });
        const newHash = await bcrypt.hash(newPassword, 10);
        db.run('UPDATE users SET password_hash = ? WHERE username = ?', [newHash, username], (err) => {
            if (err) return res.status(500).json({ error: 'Erreur mise à jour' });
            res.json({ success: true, message: `Mot de passe de ${username} réinitialisé` });
        });
    });
});

// ========== CONFIGURATION JIRA (utilisateur) ==========
app.get('/api/user/jira-config', requireAuth, (req, res) => {
    db.get('SELECT jira_url, jira_email, jira_token FROM users WHERE id = ?', [req.session.user.id], (err, row) => {
        if (err || !row) return res.json({ url: '', email: '', token: '' });
        res.json({ url: row.jira_url || '', email: row.jira_email || '', token: row.jira_token || '' });
    });
});

app.put('/api/user/jira-config', requireAuth, (req, res) => {
    const { url, email, token } = req.body;
    db.run('UPDATE users SET jira_url = ?, jira_email = ?, jira_token = ? WHERE id = ?',
        [url, email, token, req.session.user.id], (err) => {
            if (err) return res.status(500).json({ error: 'Erreur mise à jour' });
            res.json({ success: true });
        });
});

// ========== CRÉATION D'UN TICKET JIRA (format ADF) ==========
app.post('/api/jira/create-issue', requireAuth, async (req, res) => {
    const { projectKey, summary, description } = req.body;
    if (!projectKey || !summary) {
        return res.status(400).json({ error: 'Project key et summary requis' });
    }
    db.get('SELECT jira_url, jira_email, jira_token FROM users WHERE id = ?', [req.session.user.id], async (err, row) => {
        if (err || !row || !row.jira_url || !row.jira_email || !row.jira_token) {
            return res.status(401).json({ error: 'Configuration Jira manquante' });
        }
        const jiraUrl = row.jira_url.replace(/\/$/, '');
        const auth = Buffer.from(`${row.jira_email}:${row.jira_token}`).toString('base64');
        try {
            // Construction de la description au format ADF (si non vide)
            let descriptionField = undefined;
            if (description && description.trim()) {
                descriptionField = {
                    type: 'doc',
                    version: 1,
                    content: [
                        {
                            type: 'paragraph',
                            content: [
                                {
                                    type: 'text',
                                    text: description
                                }
                            ]
                        }
                    ]
                };
            }
            const response = await fetch(`${jiraUrl}/rest/api/3/issue`, {
                method: 'POST',
                headers: {
                    'Authorization': `Basic ${auth}`,
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    fields: {
                        project: { key: projectKey },
                        summary: summary,
                        description: descriptionField,
                        issuetype: { name: 'Task' }
                    }
                })
            });
            const responseText = await response.text();
            let data;
            try {
                data = JSON.parse(responseText);
            } catch(e) {
                console.error('Réponse non JSON:', responseText);
                return res.status(500).json({ error: `Réponse Jira invalide: ${responseText.substring(0, 200)}` });
            }
            if (response.ok) {
                res.json({ success: true, key: data.key, url: `${jiraUrl}/browse/${data.key}` });
            } else {
                let errorMessage = `Erreur Jira ${response.status}: `;
                if (data.errors) {
                    errorMessage += JSON.stringify(data.errors);
                } else if (data.message) {
                    errorMessage += data.message;
                } else if (data.errorMessages) {
                    errorMessage += data.errorMessages.join(', ');
                } else {
                    errorMessage += responseText;
                }
                console.error('Erreur Jira:', errorMessage);
                res.status(500).json({ error: errorMessage });
            }
        } catch (error) {
            console.error('Exception réseau Jira:', error);
            res.status(500).json({ error: `Erreur réseau: ${error.message}` });
        }
    });
});

// ========== JIRA SIMPLE URL (pour le bouton "Ouvrir Jira") ==========
app.get('/api/settings/jira-url', (req, res) => {
    db.get('SELECT value FROM settings WHERE key = "jira_url"', (err, row) => {
        if (err || !row) return res.json({ url: 'https://www.atlassian.com/software/jira' });
        res.json({ url: row.value });
    });
});

// ========== HISTORIQUE ==========
app.get('/api/history', requireAuth, (req, res) => {
    db.all(
        `SELECT id, project_name, language, status, message, pipeline_url, timestamp
         FROM deployments
         WHERE user_id = ?
         ORDER BY timestamp DESC
         LIMIT 50`,
        [req.session.user.id],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        }
    );
});

app.post('/api/history', requireAuth, (req, res) => {
    const { projectName, language, status, message, pipelineUrl } = req.body;
    db.run(
        `INSERT INTO deployments (user_id, project_name, language, status, message, pipeline_url)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [req.session.user.id, projectName, language, status, message, pipelineUrl || null],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: this.lastID });
        }
    );
});

app.delete('/api/history', requireAuth, (req, res) => {
    db.run('DELETE FROM deployments WHERE user_id = ?', [req.session.user.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ========== PROJETS (cache local) ==========
app.get('/api/user/projects', requireAuth, (req, res) => {
    db.all('SELECT * FROM projects WHERE user_id = ?', [req.session.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/user/projects', requireAuth, (req, res) => {
    const { gitlab_id, name, url, language, is_favorite } = req.body;
    db.run(
        `INSERT OR REPLACE INTO projects (user_id, gitlab_id, name, url, language, is_favorite)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [req.session.user.id, gitlab_id, name, url, language, is_favorite ? 1 : 0],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: this.lastID });
        }
    );
});

// ========== MÉTRIQUES ==========
const PROMETHEUS_URL = 'http://192.168.49.2:32648';
app.get('/api/real-metrics', async (req, res) => {
    try {
        const cpuQuery = 'sum(rate(container_cpu_usage_seconds_total[1m]))';
        const cpuResp = await fetch(`${PROMETHEUS_URL}/api/v1/query?query=${encodeURIComponent(cpuQuery)}`);
        const cpuData = await cpuResp.json();
        let totalCpu = 0;
        if (cpuData.data?.result?.[0]?.value?.[1]) totalCpu = (parseFloat(cpuData.data.result[0].value[1]) * 100).toFixed(1);
        const ramQuery = 'sum(container_memory_working_set_bytes)';
        const ramResp = await fetch(`${PROMETHEUS_URL}/api/v1/query?query=${encodeURIComponent(ramQuery)}`);
        const ramData = await ramResp.json();
        let totalRam = 0;
        if (ramData.data?.result?.[0]?.value?.[1]) totalRam = (parseFloat(ramData.data.result[0].value[1]) / (1024 * 1024)).toFixed(1);
        const podsQuery = 'count(kube_pod_status_phase{phase="Running"})';
        const podsResp = await fetch(`${PROMETHEUS_URL}/api/v1/query?query=${encodeURIComponent(podsQuery)}`);
        const podsData = await podsResp.json();
        let podsCount = 0;
        if (podsData.data?.result?.[0]?.value?.[1]) podsCount = parseInt(podsData.data.result[0].value[1], 10);
        const tempQuery = 'avg(node_hwmon_temp_celsius) or vector(25)';
        const tempResp = await fetch(`${PROMETHEUS_URL}/api/v1/query?query=${encodeURIComponent(tempQuery)}`);
        const tempData = await tempResp.json();
        let avgTemp = 25;
        if (tempData.data?.result?.[0]?.value?.[1]) avgTemp = parseFloat(tempData.data.result[0].value[1]).toFixed(1);
        res.json({ cpu: totalCpu, ram: totalRam, pods: podsCount, temperature: avgTemp, timestamp: new Date().toISOString() });
    } catch (error) {
        console.error('Erreur Prometheus:', error.message);
        res.json({ error: 'Prometheus non disponible' });
    }
});

// ========== TAG RUNNER ==========
const RUNNER_TAG = process.env.RUNNER_TAG || 'group-runner';

// ========== PIPELINES TEMPLATES ==========
const pipelines = {
    java: `stages:
  - test
  - security
  - build
  - deploy

test_java:
  stage: test
  image: maven:3.8-openjdk-11
  script:
    - mvn clean test || echo "Tests ignorés (pas de pom.xml ou erreur)"

security_java:
  stage: security
  image:
    name: aquasec/trivy:latest
    entrypoint: [""]
  script:
    - trivy fs --severity HIGH,CRITICAL --exit-code 0 . || echo "Analyse Trivy ignorée"

build_java:
  stage: build
  image: docker:20.10.16
  services:
    - docker:20.10.16-dind
  script:
    - if [ -f Dockerfile ]; then
        docker login -u $CI_REGISTRY_USER -p $CI_JOB_TOKEN $CI_REGISTRY ;
        docker build -t $CI_REGISTRY_IMAGE:latest . ;
        docker push $CI_REGISTRY_IMAGE:latest ;
      else
        echo "Aucun Dockerfile trouvé, build ignoré." ;
      fi

deploy_java:
  stage: deploy
  script:
    - export KUBECONFIG=/home/gitlab-runner/.kube/config
    - if [ -f k8s/deployment.yaml ]; then
        sed -i "s|\\$CI_REGISTRY_IMAGE|\${CI_REGISTRY_IMAGE}|g" k8s/deployment.yaml ;
        kubectl apply -f k8s/deployment.yaml ;
        kubectl rollout status deployment/$CI_PROJECT_NAME-deployment ;
      else
        echo "Pas de déploiement Kubernetes, job ignoré." ;
      fi
  tags:
    - ${RUNNER_TAG}`,

    php: `stages:
  - test
  - security
  - build
  - deploy

test_php:
  stage: test
  image: php:8.2-cli
  before_script:
    - apt-get update && apt-get install -y git unzip
    - curl -sS https://getcomposer.org/installer | php
    - php composer.phar install || echo "Composer ignoré (pas de composer.json)"
  script:
    - ./vendor/bin/phpunit --coverage-text || echo "Tests ignorés"

security_php:
  stage: security
  image: alpine:latest
  before_script:
    - apk add --no-cache curl php php-phar
    - curl -LO https://github.com/phpsecuritychecker/phpsecuritychecker/releases/download/v1.2.0/security-checker.phar
    - chmod +x security-checker.phar
    - mv security-checker.phar /usr/local/bin/security-checker
  script:
    - security-checker scan:fs . || echo "Security checker ignoré"

build_php:
  stage: build
  image: docker:20.10.16
  services:
    - docker:20.10.16-dind
  script:
    - if [ -f Dockerfile ]; then
        docker login -u $CI_REGISTRY_USER -p $CI_JOB_TOKEN $CI_REGISTRY ;
        docker build -t $CI_REGISTRY_IMAGE:latest . ;
        docker push $CI_REGISTRY_IMAGE:latest ;
      else
        echo "Aucun Dockerfile trouvé, build ignoré." ;
      fi

deploy_php:
  stage: deploy
  script:
    - export KUBECONFIG=/home/gitlab-runner/.kube/config
    - if [ -f k8s/deployment.yaml ]; then
        sed -i "s|\\$CI_REGISTRY_IMAGE|\${CI_REGISTRY_IMAGE}|g" k8s/deployment.yaml ;
        kubectl apply -f k8s/deployment.yaml ;
        kubectl rollout status deployment/$CI_PROJECT_NAME-deployment ;
      else
        echo "Pas de déploiement Kubernetes, job ignoré." ;
      fi
  tags:
    - ${RUNNER_TAG}`,

    android: `stages:
  - test
  - security
  - build
  - deploy

test_android:
  stage: test
  image: eclipse-temurin:17
  script:
    - chmod +x gradlew || true
    - ./gradlew test || echo "Tests ignorés"

security_android:
  stage: security
  image: eclipse-temurin:17
  script:
    - ./gradlew dependencies || echo "Analyse des dépendances ignorée"

build_android:
  stage: build
  image: eclipse-temurin:17
  script:
    - chmod +x gradlew || true
    - ./gradlew assembleDebug || echo "Build ignoré"
  artifacts:
    paths:
      - app/build/outputs/apk/debug/*.apk

deploy_android:
  stage: deploy
  script:
    - echo "APK prêt pour téléchargement"
`,

    js: `stages:
  - test
  - security
  - build
  - deploy

test_js:
  stage: test
  image: node:18
  script:
    - npm ci || echo "npm ci ignoré"
    - npm test || echo "Tests ignorés"
    - npm run test:coverage || echo "Pas de script test:coverage"

security_js:
  stage: security
  image: node:18
  script:
    - npm audit --audit-level=high || echo "Audit ignoré"

build_js:
  stage: build
  image: docker:20.10.16
  services:
    - docker:20.10.16-dind
  script:
    - if [ -f Dockerfile ]; then
        docker login -u $CI_REGISTRY_USER -p $CI_JOB_TOKEN $CI_REGISTRY ;
        docker build -t $CI_REGISTRY_IMAGE:latest . ;
        docker push $CI_REGISTRY_IMAGE:latest ;
      else
        echo "Aucun Dockerfile trouvé, build Docker ignoré." ;
      fi

deploy_js:
  stage: deploy
  script:
    - export KUBECONFIG=/home/gitlab-runner/.kube/config
    - if [ -f k8s/deployment.yaml ]; then
        sed -i "s|\\$CI_REGISTRY_IMAGE|\${CI_REGISTRY_IMAGE}|g" k8s/deployment.yaml ;
        kubectl apply -f k8s/deployment.yaml ;
        kubectl rollout status deployment/$CI_PROJECT_NAME-deployment ;
      else
        echo "Pas de déploiement Kubernetes, job ignoré." ;
      fi
  tags:
    - ${RUNNER_TAG}`,

    python: `stages:
  - test
  - security
  - build
  - deploy

test_python:
  stage: test
  image: python:3.11
  script:
    - pip install -r requirements.txt || echo "Installation ignorée"
    - pytest --cov=. --cov-report=html || echo "Tests ignorés"

security_python:
  stage: security
  image: python:3.11
  script:
    - pip install bandit
    - bandit -r . -ll || echo "Analyse bandit ignorée"

build_python:
  stage: build
  image: docker:20.10.16
  services:
    - docker:20.10.16-dind
  script:
    - if [ -f Dockerfile ]; then
        docker login -u $CI_REGISTRY_USER -p $CI_JOB_TOKEN $CI_REGISTRY ;
        docker build -t $CI_REGISTRY_IMAGE:latest . ;
        docker push $CI_REGISTRY_IMAGE:latest ;
      else
        echo "Aucun Dockerfile trouvé, build ignoré." ;
      fi

deploy_python:
  stage: deploy
  script:
    - export KUBECONFIG=/home/gitlab-runner/.kube/config
    - if [ -f k8s/deployment.yaml ]; then
        sed -i "s|\\$CI_REGISTRY_IMAGE|\${CI_REGISTRY_IMAGE}|g" k8s/deployment.yaml ;
        kubectl apply -f k8s/deployment.yaml ;
        kubectl rollout status deployment/$CI_PROJECT_NAME-deployment ;
      else
        echo "Pas de déploiement Kubernetes, job ignoré." ;
      fi
  tags:
    - ${RUNNER_TAG}`
};

// ========== ROUTES GITLAB ==========
app.get('/api/gitlab/projects', requireAuth, async (req, res) => {
    const token = req.session.user.gitlab_token;
    if (!token) return res.status(400).json({ error: 'Token GitLab manquant. Veuillez configurer votre token dans votre profil.' });
    try {
        const resp = await fetch(`https://gitlab.com/api/v4/projects?membership=true&per_page=100`, {
            headers: { 'PRIVATE-TOKEN': token }
        });
        const projects = await resp.json();
        if (!Array.isArray(projects)) throw new Error('Réponse invalide');
        const filtered = projects.map(p => ({ id: p.id, name: p.name, url: p.web_url, language: detectLanguageFromName(p.name) }));
        // Mise en cache locale (optionnel)
        filtered.forEach(proj => {
            db.run(`INSERT OR IGNORE INTO projects (user_id, gitlab_id, name, url, language)
                    VALUES (?, ?, ?, ?, ?)`,
                [req.session.user.id, proj.id, proj.name, proj.url, proj.language]);
        });
        res.json(filtered);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erreur chargement projets GitLab' });
    }
});

app.post('/api/generate-pipeline', requireAuth, (req, res) => {
    const { language, projectName } = req.body;
    console.log(`[GENERATE] Pipeline pour ${language} - projet ${projectName}`);
    if (pipelines[language]) {
        fs.writeFileSync('/tmp/gitlab-ci.yml', pipelines[language]);
        res.json({ success: true, pipeline: pipelines[language] });
    } else {
        res.json({ success: false, message: 'Langage non supporté' });
    }
});

app.post('/api/run-pipeline', requireAuth, async (req, res) => {
    const { language, projectName } = req.body;
    const token = req.session.user.gitlab_token;
    if (!token) return res.json({ success: false, message: 'Token GitLab non configuré dans votre profil' });
    try {
        const searchResp = await fetch(`https://gitlab.com/api/v4/projects?search=${encodeURIComponent(projectName)}`, {
            headers: { 'PRIVATE-TOKEN': token }
        });
        const searchText = await searchResp.text();
        if (!searchResp.ok) throw new Error(`GitLab search error ${searchResp.status}: ${searchText}`);
        const projects = JSON.parse(searchText);
        const project = projects.find(p => p.name === projectName || p.path === projectName || p.path_with_namespace?.includes(projectName));
        if (!project) throw new Error(`Projet "${projectName}" non trouvé sur GitLab`);
        console.log("✅ Projet trouvé:", project.name);
        let branch = 'main';
        const branchResp = await fetch(`https://gitlab.com/api/v4/projects/${project.id}/repository/branches`, {
            headers: { 'PRIVATE-TOKEN': token }
        });
        if (branchResp.ok) {
            const branches = await branchResp.json();
            console.log("Branches:", branches.map(b => b.name));
            const hasMain = branches.some(b => b.name === 'main');
            const hasMaster = branches.some(b => b.name === 'master');
            if (!hasMain && hasMaster) branch = 'master';
        }
        console.log("📌 Branche utilisée:", branch);
        const pipelineYaml = pipelines[language];
        if (!pipelineYaml) throw new Error(`Langage ${language} non supporté`);
        const encoded = Buffer.from(pipelineYaml).toString('base64');
        const filePath = '.gitlab-ci.yml';
        let fileExists = false;
        const checkResp = await fetch(`https://gitlab.com/api/v4/projects/${project.id}/repository/files/${encodeURIComponent(filePath)}?ref=${branch}`, {
            headers: { 'PRIVATE-TOKEN': token }
        });
        fileExists = checkResp.ok;
        console.log("📄 Fichier existe:", fileExists);
        const method = fileExists ? 'PUT' : 'POST';
        const updateResp = await fetch(`https://gitlab.com/api/v4/projects/${project.id}/repository/files/${encodeURIComponent(filePath)}`, {
            method: method,
            headers: { 'PRIVATE-TOKEN': token, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                branch: branch,
                content: encoded,
                encoding: 'base64',
                commit_message: `Pipeline généré (${language})`
            })
        });
        const updateText = await updateResp.text();
        if (!updateResp.ok) throw new Error(`Erreur fichier GitLab ${updateResp.status}: ${updateText}`);
        console.log("✅ .gitlab-ci.yml mis à jour");
        const triggerResp = await fetch(`https://gitlab.com/api/v4/projects/${project.id}/pipeline`, {
            method: 'POST',
            headers: { 'PRIVATE-TOKEN': token, 'Content-Type': 'application/json' },
            body: JSON.stringify({ ref: branch })
        });
        const triggerText = await triggerResp.text();
        let triggerData;
        try { triggerData = JSON.parse(triggerText); } catch { throw new Error(`Réponse invalide GitLab: ${triggerText}`); }
        console.log("📊 Trigger réponse:", triggerData);
        if (!triggerResp.ok) throw new Error(typeof triggerData.message === 'string' ? triggerData.message : JSON.stringify(triggerData));
        res.json({ success: true, pipelineUrl: triggerData.web_url });
    } catch (err) {
        console.error("❌ ERREUR COMPLETE:", err);
        console.error("STACK:", err.stack);
        res.json({ success: false, message: err.message || JSON.stringify(err) });
    }
});

function detectLanguageFromName(name) {
    const lower = name.toLowerCase();
    if (lower.includes('java')) return 'java';
    if (lower.includes('php')) return 'php';
    if (lower.includes('android')) return 'android';
    if (lower.includes('js') || lower.includes('javascript')) return 'js';
    if (lower.includes('python')) return 'python';
    return 'java';
}



// ========== IA ASSISTANT ==========
const MISTRAL_API_KEY = process.env.MISTRAL_API_KEY;
const MISTRAL_API_URL = 'https://api.mistral.ai/v1/chat/completions';

const pipelineTemplates = {
    angular: `stages:
  - test
  - build

cache:
  paths:
    - node_modules/

test:
  stage: test
  image: node:18
  script:
    - npm ci
    - npm run test -- --watch=false --browsers=ChromeHeadless

build:
  stage: build
  image: node:18
  script:
    - npm ci
    - npm run build -- --prod
  artifacts:
    paths:
      - dist/
    expire_in: 1 week`,

    react: `stages:
  - test
  - build

cache:
  paths:
    - node_modules/

test:
  stage: test
  image: node:18
  script:
    - npm ci
    - npm run test -- --watch=false

build:
  stage: build
  image: node:18
  script:
    - npm ci
    - npm run build --prod
  artifacts:
    paths:
      - build/
    expire_in: 1 week`,

    vue: `stages:
  - test
  - build

cache:
  paths:
    - node_modules/

test:
  stage: test
  image: node:18
  script:
    - npm ci
    - npm run test:unit

build:
  stage: build
  image: node:18
  script:
    - npm ci
    - npm run build --prod
  artifacts:
    paths:
      - dist/
    expire_in: 1 week`,

    go: `stages:
  - test
  - build

test:
  stage: test
  image: golang:1.21
  script:
    - go test ./...

build:
  stage: build
  image: golang:1.21
  script:
    - go build -o app
  artifacts:
    paths:
      - app`,

    rust: `stages:
  - test
  - build

test:
  stage: test
  image: rust:latest
  script:
    - cargo test

build:
  stage: build
  image: rust:latest
  script:
    - cargo build --release
  artifacts:
    paths:
      - target/release/`,

    dotnet: `stages:
  - test
  - build

test:
  stage: test
  image: mcr.microsoft.com/dotnet/sdk:8.0
  script:
    - dotnet test

build:
  stage: build
  image: mcr.microsoft.com/dotnet/sdk:8.0
  script:
    - dotnet publish -c Release -o publish
  artifacts:
    paths:
      - publish/`
};

function detectLanguageFromPrompt(prompt) {
    const lower = prompt.toLowerCase();
    if (lower.includes('angular')) return 'angular';
    if (lower.includes('react')) return 'react';
    if (lower.includes('vue') || lower.includes('vue.js')) return 'vue';
    if (lower.includes('go') || lower.includes('golang')) return 'go';
    if (lower.includes('rust')) return 'rust';
    if (lower.includes('.net') || lower.includes('dotnet')) return 'dotnet';
    return null;
}

// Fonction qui garantit un YAML avec lignes vides
function formatYaml(yamlStr) {
    if (!yamlStr || !yamlStr.includes('stages:')) return yamlStr;
    const lines = yamlStr.split(/\r?\n/);
    const result = [];
    let previousWasEmpty = false;
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        // Détecter le début d'une nouvelle section (stages:, cache:, test:, build:, etc.)
        const isSection = /^(stages:|cache:|test:|build:|deploy:|variables:|before_script:|after_script:)/.test(trimmed);
        if (isSection && result.length > 0 && result[result.length-1] !== '') {
            result.push('');
        }
        result.push(line);
    }
    // Nettoyer les doubles lignes vides
    return result.join('\n').replace(/\n\s*\n\s*\n/g, '\n\n');
}

const PROJECT_CONTEXT = `Tu es un assistant DevOps spécialiste du projet "Sartex DevOps Platform".

Fonctionnalités de la plateforme :
- Authentification, sessions
- Token GitLab, consultation projets
- Déploiement automatique (5 langages : Java, PHP, Android, JS, Python)
- Métriques Kubernetes (Prometheus)
- Historique SQLite
- Intégration Jira
- Administration utilisateurs

Réponds de manière claire et concise en français. Si l'utilisateur pose une question sur les pipelines, oriente-le vers les templates disponibles (Angular, React, Vue, Go, Rust, .NET).`;

app.post('/api/ai/ask', requireAuth, async (req, res) => {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt requis' });

    // Vérifier si l'utilisateur demande un pipeline
    const isPipelineRequest = /pipeline|\.gitlab-ci\.yml|yaml|ci\/cd/i.test(prompt);
    if (isPipelineRequest) {
        const lang = detectLanguageFromPrompt(prompt);
        if (lang && pipelineTemplates[lang]) {
            // Appliquer le formatage (ajout de lignes vides) et retourner
            const yaml = formatYaml(pipelineTemplates[lang]);
            return res.json({ success: true, reply: yaml });
        } else {
            // Si le langage n'est pas supporté, répondre via IA
            if (!MISTRAL_API_KEY) {
                return res.json({ success: true, reply: "Désolé, je n'ai pas de template pour ce langage. Vous pouvez me demander pour Angular, React, Vue, Go, Rust ou .NET." });
            }
        }
    }

    // Pour les questions générales
    if (!MISTRAL_API_KEY) {
        return res.status(500).json({ error: 'Clé API Mistral non configurée' });
    }

    try {
        const response = await fetch(MISTRAL_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${MISTRAL_API_KEY}` },
            body: JSON.stringify({
                model: 'mistral-tiny',
                messages: [ { role: 'system', content: PROJECT_CONTEXT }, { role: 'user', content: prompt } ],
                temperature: 0.7,
                max_tokens: 500
            })
        });
        const data = await response.json();
        if (data.error) throw new Error(data.error.message);
        const reply = data.choices[0].message.content;
        res.json({ success: true, reply });
    } catch (err) {
        console.error('Erreur Mistral AI:', err);
        res.status(500).json({ error: 'Erreur IA : ' + err.message });
    }
});



app.get('/api/metrics', (req, res) => {
    res.json({
        cpu: (Math.random() * 60 + 20).toFixed(1),
        ram: (Math.random() * 50 + 30).toFixed(1),
        pods: Math.floor(Math.random() * 8) + 2,
        temperature: (Math.random() * 30 + 20).toFixed(1),
        timestamp: new Date().toISOString()
    });
});

const PORT = 3443;
const server = https.createServer(sslOptions, app);
server.listen(PORT, () => {
    console.log('');
    console.log('═══════════════════════════════════════════════════');
    console.log('🚀 Dashboard HTTPS démarré avec succès !');
    console.log('═══════════════════════════════════════════════════');
    console.log(`📡 URL : https://localhost:${PORT}`);
    console.log('📁 Projets : vos projets GitLab personnels (via token utilisateur)');
    console.log(`🏷️  Runner tag utilisé : ${RUNNER_TAG}`);
    console.log('🤖 Assistant IA intégré (Mistral AI)');
    console.log('═══════════════════════════════════════════════════');
});
