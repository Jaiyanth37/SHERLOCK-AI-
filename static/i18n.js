(function () {
  'use strict';

  const languageSelect = document.getElementById('sherlockLanguage');
  if (!languageSelect) return;

  const DICT = {
    ta: {
      'SHERLOCK — Cyber Intelligence System':'SHERLOCK — சைபர் நுண்ணறிவு அமைப்பு',
      'SHERLOCK INTELLIGENCE SYSTEM':'SHERLOCK நுண்ணறிவு அமைப்பு',
      'OBSERVE • ANALYZE • DEDUCE':'கவனி • பகுப்பாய்வு செய் • முடிவு செய்',
      'INITIALIZING CYBER INTELLIGENCE ENGINE...':'சைபர் நுண்ணறிவு இயந்திரம் தொடங்கப்படுகிறது...',
      'SYSTEM ONLINE':'அமைப்பு ஆன்லைனில் உள்ளது', 'AI CORE READY':'AI மையம் தயார்', 'SECURITY ACTIVE':'பாதுகாப்பு செயல்பாட்டில்',
      'CLASSICAL AI // CYBER INTELLIGENCE':'CLASSICAL AI // சைபர் நுண்ணறிவு',
      'SHERLOCK':'SHERLOCK', 'CYBER INTELLIGENCE':'சைபர் நுண்ணறிவு',
      'A rule-based cybersecurity intelligence system that observes digital events, matches explicit security knowledge, performs logical inference, and explains every conclusion.':'டிஜிட்டல் நிகழ்வுகளை கவனித்து, தெளிவான பாதுகாப்பு அறிவுடன் பொருத்தி, தர்க்க அடிப்படையிலான முடிவெடுப்பை செய்து, ஒவ்வொரு முடிவிற்கும் விளக்கம் வழங்கும் விதி-அடிப்படையிலான சைபர் பாதுகாப்பு நுண்ணறிவு அமைப்பு.',
      'START INVESTIGATION':'விசாரணையை தொடங்கு',
      'OBSERVE • ANALYZE • MATCH RULES • DEDUCE • RECOMMEND':'கவனி • பகுப்பாய்வு செய் • விதிகளை பொருத்து • முடிவு செய் • பரிந்துரை செய்',
      'SHERLOCK // THREAT ANALYSIS':'SHERLOCK // அச்சுறுத்தல் பகுப்பாய்வு',
      'ANALYZE':'பகுப்பாய்வு', 'THREATS':'அச்சுறுத்தல்கள்',
      'Submit a URL, IP address, domain, hash, warning, event, or cybersecurity situation. Sherlock will process the input through its rule-based intelligence engine.':'URL, IP முகவரி, டொமைன், ஹாஷ், எச்சரிக்கை, நிகழ்வு அல்லது சைபர் பாதுகாப்பு சூழ்நிலையை உள்ளிடுங்கள். SHERLOCK விதி-அடிப்படையிலான நுண்ணறிவு இயந்திரத்தின் மூலம் அதை பகுப்பாய்வு செய்யும்.',
      'THREAT INTELLIGENCE ENGINE':'அச்சுறுத்தல் நுண்ணறிவு இயந்திரம்', 'THREAT INPUT':'அச்சுறுத்தல் உள்ளீடு', 'READY':'தயார்',
      'ENTER THREAT INDICATOR':'அச்சுறுத்தல் குறிகாட்டியை உள்ளிடுங்கள்', 'LANGUAGE':'மொழி', 'English':'ஆங்கிலம்', 'Tamil':'தமிழ்', 'Hindi':'இந்தி',
      'VOICE INPUT':'குரல் உள்ளீடு', 'SPEAK RESULT':'முடிவை பேசு', 'LISTENING...':'கேட்கிறது...', 'VOICE UNSUPPORTED':'குரல் ஆதரிக்கப்படவில்லை',
      'URL':'URL','IP':'IP','DOMAIN':'டொமைன்','HASH':'ஹாஷ்','BEHAVIOUR':'நடத்தை', 'START THREAT ANALYSIS':'அச்சுறுத்தல் பகுப்பாய்வை தொடங்கு',
      'AI CORE':'AI மையம்','THREAT ENGINE':'அச்சுறுத்தல் இயந்திரம்','FORENSICS':'தடயவியல்',
      'SHERLOCK // INTELLIGENCE REPORT':'SHERLOCK // நுண்ணறிவு அறிக்கை','ANALYSIS RESULT':'பகுப்பாய்வு முடிவு','COMPLETE':'முடிந்தது',
      'SHERLOCK // KNOWLEDGE BASE':'SHERLOCK // அறிவுத் தளம்','THREAT':'அச்சுறுத்தல்','KNOWLEDGE':'அறிவு','Explore the cybersecurity knowledge base used by Sherlock\'s rule-based reasoning engine.':'SHERLOCK பயன்படுத்தும் விதி-அடிப்படையிலான சைபர் பாதுகாப்பு அறிவுத் தளத்தை ஆராயுங்கள்.',
      'MEDIA FORENSICS':'மீடியா தடயவியல்','SHERLOCK // DIGITAL FORENSICS':'SHERLOCK // டிஜிட்டல் தடயவியல்',
      'Inspect images and PDFs for file details, EXIF/document metadata, hashes, structural signals and metadata-based AI/editing clues. Metadata alone cannot prove that content was created by AI.':'படங்கள் மற்றும் PDF கோப்புகளின் கோப்பு விவரங்கள், EXIF/ஆவண மெட்டாடேட்டா, ஹாஷ்கள், கட்டமைப்பு குறியீடுகள் மற்றும் மெட்டாடேட்டா அடிப்படையிலான AI/திருத்தக் குறிகளை ஆய்வு செய்க. மெட்டாடேட்டா மட்டும் உள்ளடக்கம் AI மூலம் உருவாக்கப்பட்டது என்பதை நிரூபிக்காது.',
      'UPLOAD IMAGE / PDF':'படம் / PDF பதிவேற்று','Drag and drop a file here or choose one from your computer.':'கோப்பை இங்கே இழுத்து விடுங்கள் அல்லது உங்கள் கணினியில் இருந்து தேர்வு செய்யுங்கள்.','CHOOSE FILE':'கோப்பை தேர்வு செய்','NO FILE SELECTED':'கோப்பு தேர்வு செய்யப்படவில்லை','FORENSIC ENGINE READY':'தடயவியல் இயந்திரம் தயார்',
      'SHERLOCK CYBER INTELLIGENCE SYSTEM':'SHERLOCK சைபர் நுண்ணறிவு அமைப்பு','SYSTEM SECURE':'அமைப்பு பாதுகாப்பாக உள்ளது',
      'FILE IDENTIFICATION':'கோப்பு அடையாளம்','FORENSIC DETAILS':'தடயவியல் விவரங்கள்','FORENSIC ASSESSMENT':'தடயவியல் மதிப்பீடு','EXIF METADATA':'EXIF மெட்டாடேட்டா','PDF METADATA':'PDF மெட்டாடேட்டா','FORENSIC NOTES':'தடயவியல் குறிப்புகள்',
      'ANALYZING':'பகுப்பாய்வு செய்கிறது','ANALYSIS COMPLETE':'பகுப்பாய்வு முடிந்தது','ENGINE ERROR':'இயந்திர பிழை','SHERLOCK ENGINE ERROR':'SHERLOCK இயந்திர பிழை','ANALYZING THREAT INDICATOR':'அச்சுறுத்தல் குறிகாட்டி பகுப்பாய்வு செய்யப்படுகிறது',
      'WHY SHERLOCK FLAGGED THIS':'SHERLOCK இதை ஏன் குறித்தது','RECOMMENDED ACTION':'பரிந்துரைக்கப்பட்ட நடவடிக்கை','QUESTION TYPE':'கேள்வி வகை','IOC TYPE':'IOC வகை','UNKNOWN':'தெரியவில்லை','MATCHED INDICATORS':'பொருந்திய குறிகாட்டிகள்','BEHAVIOURAL SIGNALS':'நடத்தை குறியீடுகள்','URL SIGNALS':'URL குறியீடுகள்','RELATED THREATS':'தொடர்புடைய அச்சுறுத்தல்கள்',
      'EXTRACTING FORENSIC DATA...':'தடயவியல் தரவு பிரித்தெடுக்கப்படுகிறது...','FORENSIC ANALYSIS COMPLETE':'தடயவியல் பகுப்பாய்வு முடிந்தது','ANALYSIS FAILED':'பகுப்பாய்வு தோல்வியடைந்தது','ERROR':'பிழை','INCONCLUSIVE':'தெளிவான முடிவு இல்லை','YES':'ஆம்','NO':'இல்லை','Not available':'கிடைக்கவில்லை','No EXIF metadata available':'EXIF மெட்டாடேட்டா கிடைக்கவில்லை','No document metadata available':'ஆவண மெட்டாடேட்டா கிடைக்கவில்லை',
      'File':'கோப்பு','Type':'வகை','MIME':'MIME','Size':'அளவு','Format':'வடிவம்','Dimensions':'பரிமாணங்கள்','Aspect ratio':'விகிதம்','Color mode':'நிற முறை','EXIF present':'EXIF உள்ளது','GPS':'GPS','Pages':'பக்கங்கள்','PDF version':'PDF பதிப்பு','Encrypted':'குறியாக்கம்','Creator':'உருவாக்கியவர்','Producer':'உற்பத்தியாளர்','Author':'ஆசிரியர்','Embedded images':'உட்பொதிக்கப்பட்ட படங்கள்','Fonts detected':'கண்டறியப்பட்ட எழுத்துருக்கள்'
    },
    hi: {
      'SHERLOCK — Cyber Intelligence System':'SHERLOCK — साइबर इंटेलिजेंस सिस्टम',
      'SHERLOCK INTELLIGENCE SYSTEM':'SHERLOCK इंटेलिजेंस सिस्टम','OBSERVE • ANALYZE • DEDUCE':'निरीक्षण • विश्लेषण • निष्कर्ष',
      'INITIALIZING CYBER INTELLIGENCE ENGINE...':'साइबर इंटेलिजेंस इंजन शुरू हो रहा है...','SYSTEM ONLINE':'सिस्टम ऑनलाइन','AI CORE READY':'AI कोर तैयार','SECURITY ACTIVE':'सुरक्षा सक्रिय',
      'CLASSICAL AI // CYBER INTELLIGENCE':'CLASSICAL AI // साइबर इंटेलिजेंस','CYBER INTELLIGENCE':'साइबर इंटेलिजेंस',
      'A rule-based cybersecurity intelligence system that observes digital events, matches explicit security knowledge, performs logical inference, and explains every conclusion.':'एक नियम-आधारित साइबर सुरक्षा इंटेलिजेंस सिस्टम जो डिजिटल घटनाओं का निरीक्षण करता है, सुरक्षा ज्ञान से उनका मिलान करता है, तार्किक निष्कर्ष निकालता है और हर निष्कर्ष की व्याख्या करता है.',
      'START INVESTIGATION':'जांच शुरू करें','OBSERVE • ANALYZE • MATCH RULES • DEDUCE • RECOMMEND':'निरीक्षण • विश्लेषण • नियम मिलान • निष्कर्ष • सुझाव',
      'SHERLOCK // THREAT ANALYSIS':'SHERLOCK // खतरा विश्लेषण','ANALYZE':'विश्लेषण','THREATS':'खतरे',
      'Submit a URL, IP address, domain, hash, warning, event, or cybersecurity situation. Sherlock will process the input through its rule-based intelligence engine.':'URL, IP पता, डोमेन, हैश, चेतावनी, घटना या साइबर सुरक्षा स्थिति दर्ज करें। SHERLOCK इसे अपने नियम-आधारित इंटेलिजेंस इंजन से विश्लेषित करेगा.',
      'THREAT INTELLIGENCE ENGINE':'खतरा इंटेलिजेंस इंजन','THREAT INPUT':'खतरा इनपुट','READY':'तैयार','ENTER THREAT INDICATOR':'खतरा संकेतक दर्ज करें','LANGUAGE':'भाषा','English':'अंग्रेज़ी','Tamil':'तमिल','Hindi':'हिंदी',
      'VOICE INPUT':'वॉइस इनपुट','SPEAK RESULT':'परिणाम बोलें','LISTENING...':'सुन रहा है...','VOICE UNSUPPORTED':'वॉइस समर्थित नहीं', 'URL':'URL','IP':'IP','DOMAIN':'डोमेन','HASH':'हैश','BEHAVIOUR':'व्यवहार','START THREAT ANALYSIS':'खतरा विश्लेषण शुरू करें',
      'AI CORE':'AI कोर','THREAT ENGINE':'खतरा इंजन','FORENSICS':'फॉरेंसिक्स','SHERLOCK // INTELLIGENCE REPORT':'SHERLOCK // इंटेलिजेंस रिपोर्ट','ANALYSIS RESULT':'विश्लेषण परिणाम','COMPLETE':'पूर्ण',
      'SHERLOCK // KNOWLEDGE BASE':'SHERLOCK // नॉलेज बेस','THREAT':'खतरा','KNOWLEDGE':'ज्ञान','Explore the cybersecurity knowledge base used by Sherlock\'s rule-based reasoning engine.':'SHERLOCK के नियम-आधारित रीजनिंग इंजन में उपयोग किए गए साइबर सुरक्षा नॉलेज बेस को देखें.',
      'MEDIA FORENSICS':'मीडिया फॉरेंसिक्स','SHERLOCK // DIGITAL FORENSICS':'SHERLOCK // डिजिटल फॉरेंसिक्स','Inspect images and PDFs for file details, EXIF/document metadata, hashes, structural signals and metadata-based AI/editing clues. Metadata alone cannot prove that content was created by AI.':'इमेज और PDF की फाइल जानकारी, EXIF/दस्तावेज़ मेटाडेटा, हैश, संरचनात्मक संकेत और मेटाडेटा-आधारित AI/एडिटिंग संकेतों की जांच करें। केवल मेटाडेटा से यह साबित नहीं किया जा सकता कि सामग्री AI से बनाई गई है.',
      'UPLOAD IMAGE / PDF':'इमेज / PDF अपलोड करें','Drag and drop a file here or choose one from your computer.':'फाइल यहां ड्रैग और ड्रॉप करें या कंप्यूटर से चुनें।','CHOOSE FILE':'फाइल चुनें','NO FILE SELECTED':'कोई फाइल नहीं चुनी गई','FORENSIC ENGINE READY':'फॉरेंसिक इंजन तैयार',
      'SHERLOCK CYBER INTELLIGENCE SYSTEM':'SHERLOCK साइबर इंटेलिजेंस सिस्टम','SYSTEM SECURE':'सिस्टम सुरक्षित',
      'FILE IDENTIFICATION':'फाइल पहचान','FORENSIC DETAILS':'फॉरेंसिक विवरण','FORENSIC ASSESSMENT':'फॉरेंसिक आकलन','EXIF METADATA':'EXIF मेटाडेटा','PDF METADATA':'PDF मेटाडेटा','FORENSIC NOTES':'फॉरेंसिक नोट्स',
      'ANALYZING':'विश्लेषण हो रहा है','ANALYSIS COMPLETE':'विश्लेषण पूरा','ENGINE ERROR':'इंजन त्रुटि','SHERLOCK ENGINE ERROR':'SHERLOCK इंजन त्रुटि','ANALYZING THREAT INDICATOR':'खतरा संकेतक का विश्लेषण हो रहा है',
      'WHY SHERLOCK FLAGGED THIS':'SHERLOCK ने इसे क्यों चिन्हित किया','RECOMMENDED ACTION':'अनुशंसित कार्रवाई','QUESTION TYPE':'प्रश्न प्रकार','IOC TYPE':'IOC प्रकार','UNKNOWN':'अज्ञात','MATCHED INDICATORS':'मिलान किए गए संकेतक','BEHAVIOURAL SIGNALS':'व्यवहार संकेत','URL SIGNALS':'URL संकेत','RELATED THREATS':'संबंधित खतरे',
      'EXTRACTING FORENSIC DATA...':'फॉरेंसिक डेटा निकाला जा रहा है...','FORENSIC ANALYSIS COMPLETE':'फॉरेंसिक विश्लेषण पूरा','ANALYSIS FAILED':'विश्लेषण विफल','ERROR':'त्रुटि','INCONCLUSIVE':'निष्कर्ष स्पष्ट नहीं','YES':'हाँ','NO':'नहीं','Not available':'उपलब्ध नहीं','No EXIF metadata available':'EXIF मेटाडेटा उपलब्ध नहीं','No document metadata available':'दस्तावेज़ मेटाडेटा उपलब्ध नहीं',
      'File':'फाइल','Type':'प्रकार','MIME':'MIME','Size':'आकार','Format':'फॉर्मेट','Dimensions':'आयाम','Aspect ratio':'आस्पेक्ट रेशियो','Color mode':'कलर मोड','EXIF present':'EXIF मौजूद','GPS':'GPS','Pages':'पेज','PDF version':'PDF संस्करण','Encrypted':'एन्क्रिप्टेड','Creator':'निर्माता','Producer':'प्रोड्यूसर','Author':'लेखक','Embedded images':'एम्बेडेड इमेज','Fonts detected':'पता चले फॉन्ट'
    }
  };

  const originals = new WeakMap();
  const attrOriginals = new WeakMap();
  const ATTRS = ['placeholder','aria-label','title'];

  function rememberText(node) {
    if (!originals.has(node)) originals.set(node, node.nodeValue);
    return originals.get(node);
  }

  function translateRoot(root, lang) {
    const dict = DICT[lang] || {};
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    let n;
    while ((n = walker.nextNode())) nodes.push(n);
    nodes.forEach(node => {
      if (!node.parentElement || ['SCRIPT','STYLE','NOSCRIPT'].includes(node.parentElement.tagName)) return;
      const original = rememberText(node);
      const key = original.trim();
      if (!key) return;
      if (dict[key]) {
        const lead = original.match(/^\s*/)?.[0] || '';
        const trail = original.match(/\s*$/)?.[0] || '';
        node.nodeValue = lead + dict[key] + trail;
      } else if (lang === 'en') {
        node.nodeValue = original;
      }
    });

    root.querySelectorAll?.('*').forEach(el => {
      ATTRS.forEach(attr => {
        if (!el.hasAttribute(attr)) return;
        if (!attrOriginals.has(el)) attrOriginals.set(el, {});
        const saved = attrOriginals.get(el);
        if (!(attr in saved)) saved[attr] = el.getAttribute(attr);
        const original = saved[attr];
        if (dict[original]) el.setAttribute(attr, dict[original]);
        else if (lang === 'en') el.setAttribute(attr, original);
      });
    });

    document.documentElement.lang = lang === 'ta' ? 'ta' : lang === 'hi' ? 'hi' : 'en';
    const titleDict = dict['SHERLOCK — Cyber Intelligence System'];
    document.title = lang === 'en' ? 'SHERLOCK — Cyber Intelligence System' : (titleDict || document.title);
  }

  function currentLang() {
    return languageSelect.value.startsWith('ta') ? 'ta' : languageSelect.value.startsWith('hi') ? 'hi' : 'en';
  }

  function applyLanguage(animate) {
    const lang = currentLang();
    translateRoot(document.body, lang);
    if (animate) {
      languageSelect.classList.remove('language-switching');
      void languageSelect.offsetWidth;
      languageSelect.classList.add('language-switching');
      setTimeout(() => languageSelect.classList.remove('language-switching'), 700);
    }
    window.dispatchEvent(new CustomEvent('sherlock-language-changed', { detail: { lang, locale: languageSelect.value } }));
  }

  languageSelect.addEventListener('change', () => applyLanguage(true));
  window.sherlockTranslate = applyLanguage;

  const observer = new MutationObserver(mutations => {
    if (!languageSelect.value || currentLang() === 'en') return;
    mutations.forEach(m => m.addedNodes.forEach(node => {
      if (node.nodeType === Node.ELEMENT_NODE) translateRoot(node, currentLang());
      else if (node.nodeType === Node.TEXT_NODE && node.parentElement) translateRoot(node.parentElement, currentLang());
    }));
  });
  observer.observe(document.body, { childList: true, subtree: true });

  window.addEventListener('load', () => setTimeout(() => applyLanguage(false), 250));
})();
