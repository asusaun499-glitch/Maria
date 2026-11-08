import { initializeApp } from 'https://www.gstatic.com/firebasejs/13.2.0/firebase-app.js';
import { getAuth, signInWithCustomToken } from 'https://www.gstatic.com/firebasejs/13.2.0/firebase-auth.js';
import { getStorage, ref, uploadBytesResumable, getDownloadURL } from 'https://www.gstatic.com/firebasejs/13.2.0/firebase-storage.js';

const app = initializeApp({
  apiKey: 'AIzaSyBDF6zp9Eyhe_WfUB97dy-XvvB98-gmdcQ',
  authDomain: 'maria-music.firebaseapp.com',
  projectId: 'maria-music',
  storageBucket: 'maria-music.firebasestorage.app',
  messagingSenderId: '1063183820189',
  appId: '1:1063183820189:web:224ade40824a2f7c553b74'
});
const auth = getAuth(app);
const storage = getStorage(app);

window.mariaUploadFile = async (file, onProgress = () => {}) => {
  if (!auth.currentUser) {
    const token = await window.mariaFirebaseToken();
    await signInWithCustomToken(auth, token);
  }
  const safeName = file.name.normalize('NFKD').replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '').slice(-90) || 'media';
  const path = `songs/${auth.currentUser.uid}/${crypto.randomUUID()}-${safeName}`;
  const task = uploadBytesResumable(ref(storage, path), file, {
    contentType: file.type,
    cacheControl: 'public,max-age=31536000,immutable'
  });
  await new Promise((resolve, reject) => task.on('state_changed', snapshot => {
    onProgress(Math.round(snapshot.bytesTransferred / snapshot.totalBytes * 100));
  }, reject, resolve));
  return getDownloadURL(task.snapshot.ref);
};
