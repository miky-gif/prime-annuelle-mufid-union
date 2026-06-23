'use strict';

const fs = require('fs');
const path = require('path');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

// ---------------------------------------------------------------------------
// Initialisation des identifiants Firebase (SDK Admin).
// Deux methodes possibles, dans cet ordre :
//   1. FIREBASE_KEY_PATH  -> chemin vers un fichier de cle de compte de service
//      (ou la variable standard GOOGLE_APPLICATION_CREDENTIALS).
//   2. Variables separees : FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL,
//      FIREBASE_PRIVATE_KEY (les "\n" de la cle sont automatiquement restaures).
// ---------------------------------------------------------------------------
function loadCredential() {
  const keyPath =
    process.env.FIREBASE_KEY_PATH || process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (keyPath) {
    const resolved = path.isAbsolute(keyPath)
      ? keyPath
      : path.join(__dirname, keyPath);
    if (fs.existsSync(resolved)) {
      const json = JSON.parse(fs.readFileSync(resolved, 'utf8'));
      return cert(json);
    }
  }

  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  let privateKey = process.env.FIREBASE_PRIVATE_KEY;
  if (projectId && clientEmail && privateKey) {
    // Dans un .env, la cle est souvent stockee avec des "\n" litteraux.
    privateKey = privateKey.replace(/\\n/g, '\n');
    return cert({ projectId, clientEmail, privateKey });
  }

  return null;
}

const credential = loadCredential();
if (!credential) {
  throw new Error(
    'Identifiants Firebase manquants. Definissez FIREBASE_KEY_PATH (chemin vers le fichier ' +
      'de cle de compte de service) OU FIREBASE_PROJECT_ID + FIREBASE_CLIENT_EMAIL + ' +
      'FIREBASE_PRIVATE_KEY dans le fichier .env. Voir .env.example.'
  );
}

initializeApp({ credential });

const db = getFirestore();
const COLLECTION = process.env.FIREBASE_COLLECTION || 'participations';
const col = db.collection(COLLECTION);

// Formate un horodatage Firestore en "AAAA-MM-JJ HH:MM:SS" (heure locale serveur).
function formatDate(ts) {
  const d = ts && typeof ts.toDate === 'function' ? ts.toDate() : new Date();
  const p = (n) => String(n).padStart(2, '0');
  return (
    `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
    `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  );
}

module.exports = {
  db,

  // Enregistre une participation. Renvoie l'identifiant du document cree.
  async addParticipation(data) {
    const ref = await col.add({
      nom: data.nom,
      prenom: data.prenom,
      service: data.service,
      fonction: data.fonction,
      reponse: data.reponse,
      ip: data.ip || null,
      user_agent: data.user_agent || null,
      createdAt: FieldValue.serverTimestamp(),
    });
    return { id: ref.id };
  },

  // Liste les participations, de la plus recente a la plus ancienne.
  async listParticipations() {
    const snap = await col.orderBy('createdAt', 'desc').get();
    return snap.docs.map((doc) => {
      const d = doc.data();
      return {
        id: doc.id,
        nom: d.nom,
        prenom: d.prenom,
        // Repli sur l'ancien champ "departement" pour les documents anterieurs.
        service: d.service !== undefined ? d.service : d.departement || '',
        fonction: d.fonction,
        reponse: d.reponse,
        cree_le: formatDate(d.createdAt),
      };
    });
  },

  // Supprime une participation par son identifiant de document.
  async deleteParticipation(id) {
    await col.doc(String(id)).delete();
  },

  // Compte total des participations.
  async countParticipations() {
    const snap = await col.count().get();
    return snap.data().count;
  },
};
