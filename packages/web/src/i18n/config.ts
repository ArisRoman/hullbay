import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

import fr from './locales/fr.json';
import en from './locales/en.json';

const resources = {
  fr: { translation: fr },
  en: { translation: en }
};

// Français = langue par défaut du produit. Seule une préférence stockée
// (localStorage "user-language") bascule en anglais ; le navigateur n'est
// plus détecté (un OS en anglais ne doit pas imposer la langue de l'UI).
const detectionOptions = {
  order: ['localStorage'],
  lookupLocalStorage: 'user-language',
  caches: ['localStorage'],
};

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    lng: 'fr',
    fallbackLng: 'fr',
    supportedLngs: ['fr', 'en'],
    detection: detectionOptions,
    interpolation: {
      escapeValue: false,
    }
  });

export default i18n;