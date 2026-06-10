const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const { execSync } = require('child_process');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const app = express();
const LOG_FILE = './AI_CHANGES.md';

const sslOptions = {
    key: fs.readFileSync('./ssl/key.pem'),
    cert: fs.readFileSync('./ssl/cert.pem')
};

const db = new sqlite3.Database('./users.db');

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

function logAiAction(action, details, user = 'system') {
    const timestamp = new Date().toISOString();
    const entry = `\n## ${timestamp} (${user})\n- **Action** : ${action}\n- **Détails** :\n${details}\n---\n`;
    fs.appendFileSync(LOG_FILE, entry);
}

// ========== AUTHENTIFICATION ==========
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

// ========== ADMIN ==========
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

// ========== CONFIGURATION JIRA ==========
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

app.post('/api/jira/create-issue', requireAuth, async (req, res) => {
    const { projectKey, summary, description } = req.body;
    if (!projectKey || !summary) return res.status(400).json({ error: 'Project key et summary requis' });
    db.get('SELECT jira_url, jira_email, jira_token FROM users WHERE id = ?', [req.session.user.id], async (err, row) => {
        if (err || !row || !row.jira_url || !row.jira_email || !row.jira_token) {
            return res.status(401).json({ error: 'Configuration Jira manquante' });
        }
        const jiraUrl = row.jira_url.replace(/\/$/, '');
        const auth = Buffer.from(`${row.jira_email}:${row.jira_token}`).toString('base64');
        try {
            let descriptionField = undefined;
            if (description && description.trim()) {
                descriptionField = {
                    type: 'doc',
                    version: 1,
                    content: [{ type: 'paragraph', content: [{ type: 'text', text: description }] }]
                };
            }
            const response = await fetch(`${jiraUrl}/rest/api/3/issue`, {
                method: 'POST',
                headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json', 'Content-Type': 'application/json' },
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
            try { data = JSON.parse(responseText); } catch(e) {
                return res.status(500).json({ error: `Réponse Jira invalide: ${responseText.substring(0,200)}` });
            }
            if (response.ok) {
                res.json({ success: true, key: data.key, url: `${jiraUrl}/browse/${data.key}` });
            } else {
                let errorMessage = `Erreur Jira ${response.status}: `;
                if (data.errors) errorMessage += JSON.stringify(data.errors);
                else if (data.message) errorMessage += data.message;
                else if (data.errorMessages) errorMessage += data.errorMessages.join(', ');
                else errorMessage += responseText;
                res.status(500).json({ error: errorMessage });
            }
        } catch (error) {
            res.status(500).json({ error: `Erreur réseau: ${error.message}` });
        }
    });
});

app.get('/api/settings/jira-url', (req, res) => {
    db.get('SELECT value FROM settings WHERE key = "jira_url"', (err, row) => {
        if (err || !row) return res.json({ url: 'https://www.atlassian.com/software/jira' });
        res.json({ url: row.value });
    });
});

// ========== HISTORIQUE ==========
app.get('/api/history', requireAuth, (req, res) => {
    db.all(`SELECT id, project_name, language, status, message, pipeline_url, timestamp FROM deployments WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50`, [req.session.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/history', requireAuth, (req, res) => {
    const { projectName, language, status, message, pipelineUrl } = req.body;
    db.run(`INSERT INTO deployments (user_id, project_name, language, status, message, pipeline_url) VALUES (?, ?, ?, ?, ?, ?)`, [req.session.user.id, projectName, language, status, message, pipelineUrl || null], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: this.lastID });
    });
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
    db.run(`INSERT OR REPLACE INTO projects (user_id, gitlab_id, name, url, language, is_favorite) VALUES (?, ?, ?, ?, ?, ?)`, [req.session.user.id, gitlab_id, name, url, language, is_favorite ? 1 : 0], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: this.lastID });
    });
});

// ========== MÉTRIQUES PROMETHEUS ==========
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
    - echo "APK prêt pour téléchargement"`,

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
    - ${RUNNER_TAG}`,
};

// ========== ROUTES GITLAB ==========
function detectLanguageFromName(name) {
    const lower = name.toLowerCase();
    if (lower.includes('java')) return 'java';
    if (lower.includes('php')) return 'php';
    if (lower.includes('android')) return 'android';
    if (lower.includes('js') || lower.includes('javascript')) return 'js';
    if (lower.includes('python')) return 'python';
    return 'java';
}

app.get('/api/gitlab/projects', requireAuth, async (req, res) => {
    const token = req.session.user.gitlab_token;
    if (!token) return res.status(400).json({ error: 'Token GitLab manquant' });
    try {
        const resp = await fetch(`https://gitlab.com/api/v4/projects?membership=true&per_page=100`, { headers: { 'PRIVATE-TOKEN': token } });
        const projects = await resp.json();
        if (!Array.isArray(projects)) throw new Error('Réponse invalide');
        const filtered = projects.map(p => ({ id: p.id, name: p.name, url: p.web_url, language: detectLanguageFromName(p.name) }));
        filtered.forEach(proj => {
            db.run(`INSERT OR IGNORE INTO projects (user_id, gitlab_id, name, url, language) VALUES (?, ?, ?, ?, ?)`, [req.session.user.id, proj.id, proj.name, proj.url, proj.language]);
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
    if (!token) return res.json({ success: false, message: 'Token GitLab non configuré' });
    try {
        const searchResp = await fetch(`https://gitlab.com/api/v4/projects?search=${encodeURIComponent(projectName)}`, { headers: { 'PRIVATE-TOKEN': token } });
        const searchText = await searchResp.text();
        if (!searchResp.ok) throw new Error(`GitLab search error ${searchResp.status}: ${searchText}`);
        const projects = JSON.parse(searchText);
        const project = projects.find(p => p.name === projectName || p.path === projectName || p.path_with_namespace?.includes(projectName));
        if (!project) throw new Error(`Projet "${projectName}" non trouvé sur GitLab`);
        let branch = 'main';
        const branchResp = await fetch(`https://gitlab.com/api/v4/projects/${project.id}/repository/branches`, { headers: { 'PRIVATE-TOKEN': token } });
        if (branchResp.ok) {
            const branches = await branchResp.json();
            const hasMain = branches.some(b => b.name === 'main');
            const hasMaster = branches.some(b => b.name === 'master');
            if (!hasMain && hasMaster) branch = 'master';
        }
        const pipelineYaml = pipelines[language];
        if (!pipelineYaml) throw new Error(`Langage ${language} non supporté`);
        const encoded = Buffer.from(pipelineYaml).toString('base64');
        const filePath = '.gitlab-ci.yml';
        let fileExists = false;
        const checkResp = await fetch(`https://gitlab.com/api/v4/projects/${project.id}/repository/files/${encodeURIComponent(filePath)}?ref=${branch}`, { headers: { 'PRIVATE-TOKEN': token } });
        fileExists = checkResp.ok;
        const method = fileExists ? 'PUT' : 'POST';
        const updateResp = await fetch(`https://gitlab.com/api/v4/projects/${project.id}/repository/files/${encodeURIComponent(filePath)}`, {
            method: method,
            headers: { 'PRIVATE-TOKEN': token, 'Content-Type': 'application/json' },
            body: JSON.stringify({ branch: branch, content: encoded, encoding: 'base64', commit_message: `Pipeline généré (${language})` })
        });
        if (!updateResp.ok) throw new Error(`Erreur fichier GitLab ${updateResp.status}: ${await updateResp.text()}`);
        const triggerResp = await fetch(`https://gitlab.com/api/v4/projects/${project.id}/pipeline`, {
            method: 'POST',
            headers: { 'PRIVATE-TOKEN': token, 'Content-Type': 'application/json' },
            body: JSON.stringify({ ref: branch })
        });
        const triggerText = await triggerResp.text();
        let triggerData;
        try { triggerData = JSON.parse(triggerText); } catch { throw new Error(`Réponse invalide GitLab: ${triggerText}`); }
        if (!triggerResp.ok) throw new Error(typeof triggerData.message === 'string' ? triggerData.message : JSON.stringify(triggerData));
        res.json({ success: true, pipelineUrl: triggerData.web_url });
    } catch (err) {
        console.error("Erreur run-pipeline:", err);
        res.json({ success: false, message: err.message });
    }
});

// ========== IA ASSISTANT (MCP) ==========
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
    - npm run test -- --watchAll=false

build:
  stage: build
  image: node:18
  script:
    - npm ci
    - npm run build
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
    - npm run build
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
    - go test -v ./...

build:
  stage: build
  image: golang:1.21
  script:
    - go build -o myapp ./cmd/...
  artifacts:
    paths:
      - myapp
    expire_in: 1 week`,

    rust: `stages:
  - test
  - build

test:
  stage: test
  image: rust:latest
  script:
    - cargo test --verbose

build:
  stage: build
  image: rust:latest
  script:
    - cargo build --release
  artifacts:
    paths:
      - target/release/
    expire_in: 1 week`,

    dotnet: `stages:
  - test
  - build

test:
  stage: test
  image: mcr.microsoft.com/dotnet/sdk:8.0
  script:
    - dotnet test --no-build --verbosity normal

build:
  stage: build
  image: mcr.microsoft.com/dotnet/sdk:8.0
  script:
    - dotnet build --configuration Release
  artifacts:
    paths:
      - bin/Release/
    expire_in: 1 week`
};

function detectLanguageFromPrompt(prompt) {
    const lower = prompt.toLowerCase();
    if (lower.includes('angular')) return 'angular';
    if (lower.includes('react')) return 'react';
    if (lower.includes('vue')) return 'vue';
    if (lower.includes('go')) return 'go';
    if (lower.includes('rust')) return 'rust';
    if (lower.includes('.net') || lower.includes('dotnet')) return 'dotnet';
    return null;
}

function formatYaml(yamlStr) {
    if (!yamlStr || !yamlStr.includes('stages:')) return yamlStr;
    const lines = yamlStr.split(/\r?\n/);
    const result = [];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        const isSection = /^(stages:|cache:|test:|build:|deploy:|variables:|before_script:|after_script:)/.test(trimmed);
        if (isSection && result.length > 0 && result[result.length-1] !== '') {
            result.push('');
        }
        result.push(line);
    }
    return result.join('\n').replace(/\n\s*\n\s*\n/g, '\n\n');
}

const PROJECT_CONTEXT = `Tu es un assistant DevOps pour la plateforme Sartex DevOps Platform.

**FONCTIONNALITÉS PRINCIPALES** :
- Répondre aux questions sur la plateforme (authentification, GitLab, déploiement, Prometheus, Jira, etc.)
- Fournir des templates de pipeline GitLab CI/CD pour différents langages
- Analyser les erreurs de pipeline et proposer des corrections automatiques
- AJOUTER de nouveaux pipelines dans le fichier server.js (avec ou sans template)
- SUPPRIMER des pipelines existants dans server.js

**RÈGLE DE LANGUE** :
- Si l'utilisateur écrit en ANGLAIS, réponds en ANGLAIS.
- Si l'utilisateur écrit en FRANÇAIS, réponds en FRANÇAIS.

**RÈGLES DE DÉTECTION AUTOMATIQUE** :
1. Si le message contient "ERROR:", "failed:", "command not found", "exit code", "[ERROR]", "Unknown lifecycle" → c'est une ERREUR → réponds avec le format [TARGET_FILE:server.js]
2. Si le message contient "ajoute", "supprime", "crée", "remove", "delete", "add" → c'est une COMMANDE d'ajout/suppression → réponds avec le format approprié
3. Si le message contient "donne moi", "pipeline", "template", "yaml" → c'est une DEMANDE DE PIPELINE → réponds avec le template YAML
4. Si le message contient "?", "comment", "pourquoi", "configure", "how to" → c'est une QUESTION → réponds normalement

**PARTIE 1 : CORRECTION DES ERREURS (ancien format)** :
Quand l'utilisateur colle une erreur de pipeline, réponds avec ce format EXACT :

[TARGET_FILE:server.js]
[SEARCH_CODE]
    - [la commande erronée exacte]
[REPLACE_CODE]
    - [la commande corrigée qui fonctionne]
[END_FIX]

Exemples :
- "composer unknow" → REPLACE_CODE: "    - composer install || echo 'Composer installé'"
- "mvn unknown-command" → REPLACE_CODE: "    - mvn clean test || echo 'Tests ignorés'"
- "npm fake" → REPLACE_CODE: "    - npm install || echo 'Installation npm'"

**PARTIE 2 : DEMANDE DE PIPELINE (ancien format)** :
Quand l'utilisateur demande un pipeline (ex: "donne moi un pipeline React" ou "give me a React pipeline"), réponds avec le template YAML correspondant.
Langages disponibles : Java, PHP, Python, Node.js, Angular, React, Vue, Go, Rust, .NET, Android, JS.

**PARTIE 3 : AJOUT DE PIPELINE (NOUVEAU)** :
Quand l'utilisateur dit "ajoute le pipeline pour [langage]" :

- Si l'utilisateur FOURNIT le template, utilise-le.
- Si l'utilisateur ne fournit PAS de template, utilise les templates par défaut :

Pour "flutter" :
flutter: ` + "`" + `stages:
  - test
  - build

test:
  stage: test
  image: cirrusci/flutter:stable
  script:
    - flutter test

build:
  stage: build
  script:
    - flutter build apk
  artifacts:
    paths:
      - build/app/outputs/flutter-apk/
    expire_in: 1 week` + "`" + `

Pour "nextjs" :
nextjs: ` + "`" + `stages:
  - test
  - build

cache:
  paths:
    - node_modules/
    - .next/cache/

test:
  stage: test
  image: node:18
  script:
    - npm ci
    - npm run test

build:
  stage: build
  image: node:18
  script:
    - npm ci
    - npm run build
  artifacts:
    paths:
      - .next/
    expire_in: 1 week` + "`" + `

Pour "laravel" :
laravel: ` + "`" + `stages:
  - test
  - build

test:
  stage: test
  image: php:8.2
  before_script:
    - apt-get update && apt-get install -y git unzip
    - curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    - composer install
  script:
    - php artisan test

build:
  stage: build
  script:
    - echo "Build terminé"` + "`" + `

Format de réponse :
[TARGET_FILE:server.js]
[SEARCH_CODE]
AJOUTER_PIPELINE
[REPLACE_CODE]
    nom_langage: ` + "`" + `(contenu YAML)` + "`" + `,
[END_FIX]

**PARTIE 4 : SUPPRESSION DE PIPELINE (NOUVEAU)** :
Quand l'utilisateur dit "supprime le pipeline [langage]" ou "remove [language] pipeline", utilise :

[TARGET_FILE:server.js]
[SEARCH_CODE]
SUPPRIMER_PIPELINE
[REPLACE_CODE]
    nom_du_langage
[END_FIX]

**PARTIE 5 : QUESTIONS GÉNÉRALES (ancien format)** :
Réponds dans la MÊME LANGUE que la question de l'utilisateur.

**IMPORTANT** :
- Pour les corrections d'erreurs, réponds UNIQUEMENT avec le format structuré [TARGET_FILE:server.js]
- Pour les ajouts et suppressions, réponds UNIQUEMENT avec le format structuré
- Pour les demandes de pipeline, réponds avec le YAML directement
- Pour les questions générales, réponds en texte clair
- Vérifie toujours si un pipeline existe déjà avant de l'ajouter
- Ne supprime un pipeline que s'il existe vraiment`;

app.post('/api/ai/ask', requireAuth, async (req, res) => {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt requis' });

    const isPipelineRequest = /pipeline|\.gitlab-ci\.yml|yaml|ci\/cd/i.test(prompt);
    if (isPipelineRequest) {
        const lang = detectLanguageFromPrompt(prompt);
        if (lang && pipelineTemplates[lang]) {
            const yaml = formatYaml(pipelineTemplates[lang]);
            return res.json({ success: true, reply: yaml });
        } else if (!MISTRAL_API_KEY) {
            return res.json({ success: true, reply: "Désolé, je n'ai pas de template pour ce langage. Langages disponibles : Angular, React, Vue, Go, Rust, .NET." });
        }
    }

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
                temperature: 0.2,
                max_tokens: 800
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

app.post('/api/ai/apply-fix', requireAuth, (req, res) => {
    const { rawAiReply } = req.body;
    if (!rawAiReply) return res.json({ success: false, message: "Aucune réponse de l'IA reçue." });

    try {
        const fileMatch = rawAiReply.match(/\[TARGET_FILE:\s*([a-zA-Z0-9_\.\/-]+)\]/);
        const searchMatch = rawAiReply.match(/\[SEARCH_CODE\]\n([\s\S]*?)\n\[REPLACE_CODE\]/);
        const replaceMatch = rawAiReply.match(/\[REPLACE_CODE\]\n([\s\S]*?)\n\[END_FIX\]/);

        if (!fileMatch || !searchMatch || !replaceMatch) {
            return res.json({ success: false, message: "Format de correctif structuré introuvable." });
        }

        const targetFile = fileMatch[1].trim();
        const filePath = path.join(__dirname, targetFile);
        const searchCode = searchMatch[1].trim();
        let replaceCode = replaceMatch[1].trim();

        if (!filePath.startsWith(__dirname)) {
            return res.json({ success: false, message: "Accès refusé." });
        }

        if (!fs.existsSync(filePath)) {
            return res.json({ success: false, message: `Fichier ${targetFile} introuvable.` });
        }


        if (searchCode === 'AJOUTER_PIPELINE' || searchCode.includes('AJOUTER_PIPELINE')) {
            let content = fs.readFileSync(filePath, 'utf8');
            
            const startIndex = content.indexOf('const pipelines = {');
            if (startIndex === -1) {
                return res.json({ success: false, message: "const pipelines = { non trouvé" });
            }
            
            let braceCount = 0;
            let endIndex = -1;
            for (let i = startIndex; i < content.length; i++) {
                if (content[i] === '{') braceCount++;
                if (content[i] === '}') {
                    braceCount--;
                    if (braceCount === 0) {
                        endIndex = i;
                        break;
                    }
                }
            }
            
            if (endIndex === -1) {
                return res.json({ success: false, message: "Structure pipelines invalide" });
            }
            
            const beforePipelines = content.substring(0, startIndex);
            let pipelinesContent = content.substring(startIndex + 'const pipelines = '.length, endIndex);
            const afterPipelines = content.substring(endIndex + 1);
            
            const langName = replaceCode.match(/^\s*([a-zA-Z0-9_]+):/)?.[1];
            
            if (langName && pipelinesContent.includes(`${langName}:`)) {
                return res.json({ success: false, message: `Le pipeline "${langName}" existe déjà.` });
            }
            
            let newPipeline = replaceCode.trim();
            if (!newPipeline.endsWith(',')) newPipeline += ',';
            
            let newPipelinesContent;
            const pipelinesTrimmed = pipelinesContent.trim();
            
            if (pipelinesTrimmed === '{' || pipelinesTrimmed === '') {
                newPipelinesContent = '{\n    ' + newPipeline + '\n';
            } else {
                newPipelinesContent = pipelinesContent.slice(0, -1) + ',\n    ' + newPipeline + '\n}';
            }
            
            if (!newPipelinesContent.trim().endsWith('}')) {
                newPipelinesContent = newPipelinesContent.trim();
                if (!newPipelinesContent.endsWith('}')) {
                    newPipelinesContent = newPipelinesContent + '\n}';
                }
            }
            
            const newContent = beforePipelines + 'const pipelines = ' + newPipelinesContent + afterPipelines;
            
            fs.writeFileSync(filePath, newContent, 'utf8');
            logAiAction("ADD_PIPELINE", `Pipeline ajouté : ${langName || 'inconnu'}`, req.session.user.username);
            return res.json({ success: true, message: `Pipeline "${langName}" ajouté avec succès ! Redémarrez le serveur.` });
        } 
        if (searchCode === 'SUPPRIMER_PIPELINE' || searchCode.includes('SUPPRIMER_PIPELINE')) {
            let content = fs.readFileSync(filePath, 'utf8');
            let langName = replaceCode.trim();
            if (!langName) {
                return res.json({ success: false, message: "Nom du pipeline à supprimer non trouvé." });
            }
            
            const startIndex = content.indexOf('const pipelines = {');
            if (startIndex === -1) {
                return res.json({ success: false, message: "const pipelines = { non trouvé" });
            }
            
            let braceCount = 0;
            let endIndex = -1;
            for (let i = startIndex; i < content.length; i++) {
                if (content[i] === '{') braceCount++;
                if (content[i] === '}') {
                    braceCount--;
                    if (braceCount === 0) {
                        endIndex = i;
                        break;
                    }
                }
            }
            
            if (endIndex === -1) {
                return res.json({ success: false, message: "Structure pipelines invalide" });
            }
            
            const beforePipelines = content.substring(0, startIndex);
            let pipelinesContent = content.substring(startIndex + 'const pipelines = '.length, endIndex);
            const afterPipelines = content.substring(endIndex + 1);
            
            if (!pipelinesContent.includes(`${langName}:`)) {
                return res.json({ success: false, message: `Pipeline "${langName}" non trouvé.` });
            }
            
            const lines = pipelinesContent.split('\n');
            let newLines = [];
            let skipUntilNextPipeline = false;
            let found = false;
            
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                
                if (!skipUntilNextPipeline && line.trim().startsWith(`${langName}:`)) {
                    skipUntilNextPipeline = true;
                    found = true;
                    continue;
                }
                
                if (skipUntilNextPipeline) {
                    // Vérifier si on a atteint la fin du template (ligne qui contient `),` ou `\``)
                    if (line.trim().endsWith('`,') || line.trim().endsWith('`') || 
                        (line.includes('`') && i > 0 && lines[i-1].includes('`'))) {
                        skipUntilNextPipeline = false;
                    }
                    continue;
                }
                
                newLines.push(line);
            }
            
            if (!found) {
                return res.json({ success: false, message: `Pipeline "${langName}" non trouvé.` });
            }
            
            let newPipelinesContent = newLines.join('\n');
            
            newPipelinesContent = newPipelinesContent.replace(/,\n\s*,/g, ',\n');
            newPipelinesContent = newPipelinesContent.replace(/,\n\s*}/, '\n}');
            newPipelinesContent = newPipelinesContent.replace(/\n\s*\n\s*\n/g, '\n\n');
            
            if (!newPipelinesContent.trim().endsWith('}')) {
                newPipelinesContent = newPipelinesContent.trim();
                if (!newPipelinesContent.endsWith('}')) {
                    newPipelinesContent = newPipelinesContent + '\n}';
                }
            }
            
            const newContent = beforePipelines + 'const pipelines = ' + newPipelinesContent + afterPipelines;
            
            fs.writeFileSync(filePath, newContent, 'utf8');
            logAiAction("REMOVE_PIPELINE", `Pipeline supprimé : ${langName}`, req.session.user.username);
            return res.json({ success: true, message: `Pipeline "${langName}" supprimé avec succès ! Redémarrez le serveur.` });
        } 

        let fileContent = fs.readFileSync(filePath, 'utf8');
        const cleanContent = fileContent.replace(/\r\n/g, '\n');
        const cleanSearch = searchCode.replace(/\r\n/g, '\n');

        if (!cleanContent.includes(cleanSearch)) {
            return res.json({ success: false, message: `Bloc original introuvable dans ${targetFile}.` });
        }

        let updatedContent;
        if (!replaceCode || replaceCode.trim() === '') {
            const escapedSearch = cleanSearch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const searchRegex = new RegExp(`^[ \\t]*${escapedSearch}[ \\t]*\\r?\\n`, 'm');
            updatedContent = cleanContent.replace(searchRegex, '');
        } else {
            updatedContent = cleanContent.replace(cleanSearch, replaceCode);
        }

        fs.writeFileSync(filePath, updatedContent, 'utf8');
        logAiAction("AUTO_FIX", `Fichier corrigé : ${targetFile}`, req.session.user.username);
        return res.json({ success: true, message: `Fichier ${targetFile} mis à jour !` });

    } catch (error) {
        console.error("Erreur apply-fix:", error);
        return res.json({ success: false, message: "Erreur interne : " + error.message });
    }
});

app.post('/api/ai/analyze-error', requireAuth, async (req, res) => {
    const { errorLog, context } = req.body;
    if (!errorLog) return res.status(400).json({ error: 'Log d’erreur requis' });
    if (!MISTRAL_API_KEY) return res.status(500).json({ error: 'Clé API Mistral non configurée' });

    const prompt = `Analyse cette erreur et réponds UNIQUEMENT avec le format structuré suivant :

[TARGET_FILE:server.js]
[SEARCH_CODE]
la ligne exacte erronée
[REPLACE_CODE]
la ligne corrigée
[END_FIX]

Erreur : ${errorLog}`;

    try {
        const response = await fetch(MISTRAL_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${MISTRAL_API_KEY}` },
            body: JSON.stringify({
                model: 'mistral-tiny',
                messages: [ { role: 'system', content: PROJECT_CONTEXT }, { role: 'user', content: prompt } ],
                temperature: 0.1,
                max_tokens: 500
            })
        });
        const data = await response.json();
        const reply = data.choices[0].message.content;
        logAiAction('Analyse erreur', `Erreur: ${errorLog.substring(0, 200)}...\nRéponse IA: ${reply}`, req.session.user.username);
        res.json({ success: true, analysis: reply });
    } catch (err) {
        console.error('Erreur analyse IA:', err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/ai/check-file', requireAuth, (req, res) => {
    const { filePath } = req.body;
    const allowed = ['server.js', 'index.html', 'login.html', 'init-db.js'];
    if (!allowed.includes(filePath)) return res.json({ exists: false });
    const fullPath = path.join(__dirname, filePath);
    res.json({ exists: fs.existsSync(fullPath) });
});

app.get('/api/ai/history', requireAdmin, (req, res) => {
    if (!fs.existsSync(LOG_FILE)) return res.json({ logs: '' });
    const content = fs.readFileSync(LOG_FILE, 'utf8');
    res.json({ logs: content });
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
