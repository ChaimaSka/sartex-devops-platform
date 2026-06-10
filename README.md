# Sartex DevOps Platform

Plateforme DevOps pour l'automatisation des déploiements CI/CD avec assistant IA.

---

## Fonctionnalités

- Authentification sécurisée (admin / utilisateur)
- Intégration GitLab (récupération des projets)
- Déploiement multi-langages (Java, PHP, Android, JS, Python)
- Métriques Prometheus (CPU, RAM, Pods)
- Intégration Jira (création de tickets)
- Assistant IA (Mistral AI)

---

## Assistant IA

L'assistant intelligent permet de :

| Action | Commande exemple |
|--------|------------------|
| Générer un pipeline | `donne moi un pipeline React` |
| Analyser une erreur | Coller l'erreur + bouton "Analyser" |
| Corriger automatiquement | Bouton "Appliquer" (admin uniquement) |
| Ajouter un pipeline | `ajoute le pipeline pour flutter` (admin) |
| Supprimer un pipeline | `supprime le pipeline flutter` (admin) |
| Poser une question | `comment déployer un projet Java ?` |

---

## Installation

```bash
git clone https://github.com/ChaimaSka/sartex-devops-platform.git 
cd sartex-devops-platform
npm install
node server.js
