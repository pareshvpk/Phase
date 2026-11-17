# Hindi/Tamil Llama evaluation prompts

Roadmap task 1.5: 20 test messages per language (English, Hindi, Tamil) to run
through the on-device Llama explanation behind `AdviceGuard`, on the phone. Mix
of scam and safe messages: realistic Indian scams (KYC, OTP, electricity bill,
courier, job/task scam, UPI collect request, digital arrest, refund scam).

For each message: run Llama, apply `AdviceGuard` with the localized fallback,
and record whether the shown text contradicts the expected verdict. Target: 0
contradictions across all 60 messages before shipping Hindi/Tamil Llama.
Quality judging is done by the owner on a real device — do not record results
here until the phone check is done.

## English

| # | Message | Expected verdict |
|---|---------|------------------|
| 1 | Your SBI KYC is incomplete. Update your PAN now at http://sbi-kyc-update.xyz or your account will be blocked. | HIGH_RISK |
| 2 | OTP 884921 for your HDFC login. Do not share this OTP with anyone. | SAFE |
| 3 | Your electricity bill is unpaid. Pay immediately through https://pay-bill-fake.com to avoid disconnection tonight. | HIGH_RISK |
| 4 | Your courier from BlueDart is stuck at the hub due to address issue. Pay Rs 49 to release: https://courier-pay.in | HIGH_RISK |
| 5 | Congratulations! You are selected for a work-from-home task. Send Rs 1000 registration fee via UPI to start earning daily. | HIGH_RISK |
| 6 | UPI collect request of Rs 2500 from "Priya Sharma" - "Payment for groceries". Accept or decline. | SUSPICIOUS |
| 7 | Digital arrest notice: you are involved in a money laundering case. Call +91-9876543210 immediately to avoid arrest. | HIGH_RISK |
| 8 | Income tax refund of Rs 12,500 is pending. Share your bank details to receive the refund. https://tax-refund-claim.net | HIGH_RISK |
| 9 | Your Amazon order #448291 has been shipped and will arrive tomorrow. Track it on the Amazon app. | SAFE |
| 10 | Your Jio prepaid plan is active until 2026-12-01. Recharge anytime via the MyJio app. | SAFE |
| 11 | Your OTP for Paytm login is 442771. Valid for 10 minutes. | SAFE |
| 12 | Your bank account will be deactivated in 24 hours. Verify your ATM PIN here: https://verify-bank-login.com | HIGH_RISK |
| 13 | Part-time job: like YouTube videos and earn Rs 3000 per day. Message the manager on Telegram to join. | HIGH_RISK |
| 14 | Your credit card statement for March is ready. View it by logging into the net banking portal. | SAFE |
| 15 | Western Union money transfer of $500 awaits pickup. Pay the clearance fee first. | HIGH_RISK |
| 16 | Your SIM card will expire tonight. Reply with your Aadhaar number to reactivate. | HIGH_RISK |
| 17 | Your Flipkart refund of Rs 699 has been initiated and will reach your account in 3 days. | SAFE |
| 18 | Google Pay UPI collect request for Rs 100 from "Tech Support". | SUSPICIOUS |
| 19 | CBI cyber crime alert: your phone is linked to illegal activity. Pay fine to avoid case. | HIGH_RISK |
| 20 | Your monthly Netflix subscription is confirmed. No action needed. | SAFE |

## Hindi (हिन्दी)

| # | संदेश | अपेक्षित निर्णय |
|---|--------|--------------|
| 1 | आपका SBI KYC अधूरा है। अपना पैन अभी अपडेट करें http://sbi-kyc-update.xyz नहीं तो आपका खाता ब्लॉक कर दिया जाएगा। | HIGH_RISK |
| 2 | आपके एचडीएफसी लॉगिन के लिए ओटीपी 884921 है। यह ओटीपी किसी से साझा न करें। | SAFE |
| 3 | आपका बिजली का बिल बकाया है। आज रात कटाव से बचने के लिए तुरंत https://pay-bill-fake.com पर भुगतान करें। | HIGH_RISK |
| 4 | आपका ब्लूडार्ट कूरियर पता की समस्या के कारण अटका है। रिलीज करने के लिए 49 रुपये का भुगतान करें: https://courier-pay.in | HIGH_RISK |
| 5 | बधाई! आपको वर्क-फ्रॉम-होम कार्य के लिए चुना गया है। कमाई शुरू करने के लिए पंजीकरण शुल्क 1000 रुपये यूपीआई से भेजें। | HIGH_RISK |
| 6 | "प्रिया शर्मा" से 2500 रुपये का यूपीआई collect अनुरोध - "किराने का भुगतान". स्वीकार या अस्वीकार करें। | SUSPICIOUS |
| 7 | डिजिटल गिरफ्तारी नोटिस: आप धनशोधन मामले में शामिल हैं। गिरफ्तारी से बचने के लिए तुरंत +91-9876543210 पर कॉल करें। | HIGH_RISK |
| 8 | आयकर रिफंड 12,500 रुपये लंबित है। रिफंड प्राप्त करने के लिए अपने बैंक विवरण साझा करें। https://tax-refund-claim.net | HIGH_RISK |
| 9 | आपका अमेज़न ऑर्डर #448291 भेज दिया गया है और कल आएगा। अमेज़न ऐप पर ट्रैक करें। | SAFE |
| 10 | आपका जियो प्रीपेड प्लान 2026-12-01 तक सक्रिय है। कभी भी मायजियो ऐप से रिचार्ज करें। | SAFE |
| 11 | पेटीएम लॉगिन के लिए आपका ओटीपी 442771 है। 10 मिनट के लिए मान्य। | SAFE |
| 12 | 24 घंटे में आपका बैंक खाता निष्क्रिय कर दिया जाएगा। अपना एटीएम पिन सत्यापित करें: https://verify-bank-login.com | HIGH_RISK |
| 13 | अंशकालिक नौकरी: यूट्यूब वीडियो लाइक करें और प्रतिदिन 3000 रुपये कमाएं। शामिल होने के लिए प्रबंधक को टेलीग्राम पर मैसेज करें। | HIGH_RISK |
| 14 | मार्च का आपका क्रेडिट कार्ड स्टेटमेंट तैयार है। नेट बैंकिंग पोर्टल में लॉग इन करके देखें। | SAFE |
| 15 | वेस्टर्न यूनियन मनी ट्रांसफर 500 डॉलर पिकअप का इंतजार कर रहा है। क्लियरेंस शुल्क पहले चुकाएं। | HIGH_RISK |
| 16 | आपका सिम कार्ड आज रात समाप्त हो जाएगा। पुनः सक्रिय करने के लिए अपना आधार नंबर भेजें। | HIGH_RISK |
| 17 | आपके फ्लिपकार्ट रिफंड 699 रुपये की शुरुआत हो गई है और 3 दिन में आपके खाते में पहुंच जाएगा। | SAFE |
| 18 | गूगल पे यूपीआई collect अनुरोध 100 रुपये के लिए "टेक सपोर्ट" से। | SUSPICIOUS |
| 19 | सीबीआई साइबर क्राइम अलर्ट: आपका फोन अवैध गतिविधि से जुड़ा है। मामले से बचने के लिए जुर्माना चुकाएं। | HIGH_RISK |
| 20 | आपकी मासिक नेटफ्लिक्स सदस्यता पुष्टि हो गई है। कोई कार्रवाई नहीं चाहिए। | SAFE |

## Tamil (தமிழ்)

| # | செய்தி | எதிர்பார்த்த தீர்ப்பு |
|---|--------|--------------|
| 1 | உங்கள் SBI KYC முழுமையற்றது. உங்கள் பான் எண் http://sbi-kyc-update.xyz-ல் பதிவு செய்ய வேண்டும், இல்லையெனில் உங்கள் கணக்கு முடக்கப்படும். | HIGH_RISK |
| 2 | உங்கள் HDFC உள்நுழைவுக்கு OTP 884921. இந்த OTP-ஐ யாரிடமும் பகிராதீர்கள். | SAFE |
| 3 | உங்கள் மின் கட்டணம் பாக்கி உள்ளது. இன்று இரவில் மின்சாரம் நிறுத்தப்படும். | HIGH_RISK |
| 4 | உங்கள் BlueDart parcel address ஒரு சிக்கலில் உள்ளது. Parcel release pan Rs. 49 செலுத்துங்கள்: https://courier-pay.in | HIGH_RISK |
| 5 | Work from home task-க்கு நீங்கள் தேர்வு செய்யப்பட்டீர்கள். Registration fee Rs. 1000 UPI-ல் அனுப்புங்கள், தினமும் வருமானம் கிடைக்கும். | HIGH_RISK |
| 6 | 'Priya Sharma' என்னிடமிருந்து Rs. 2500 UPI collect request. Accept or decline. | SUSPICIOUS |
| 7 | Digital arrest notice: neengal money laundering case-udan involved. Kaiytu agamal irukka +91-9876543210 number-ku call pannunga. | HIGH_RISK |
| 8 | Income tax refund Rs. 12,500 pending. Bank details pannunga, refund kudukudhu. https://tax-refund-claim.net | HIGH_RISK |
| 9 | Amazon order #448291 shipped, naalai varum. Amazon app-la track pannunga. | SAFE |
| 10 | Jio prepaid plan 2026-12-01 varai active. MyJio app-la recharge pannunga. | SAFE |
| 11 | Paytm login-ku OTP 442771. 10 nimidam valid. | SAFE |
| 12 | Bank account 24 mani-la deactivate aagum. ATM PIN verify pannunga https://verify-bank-login.com | HIGH_RISK |
| 13 | Part-time job: YouTube video like panna rojaku Rs. 3000. Telegram-la manager-ku message pannunga. | HIGH_RISK |
| 14 | Credit card statement ready. Net banking portal-la login panna paanga. | SAFE |
| 15 | Western Union $500 money transfer pickup-a await. Clearance fee munda pannunga. | HIGH_RISK |
| 16 | SIM card tonight expire aagum. Reactivate aagala Aadhaar number reply pannunga. | HIGH_RISK |
| 17 | Flipkart refund Rs. 699 initiated. 3 naal-la account-la varum. | SAFE |
| 18 | Google Pay UPI collect request Rs. 100 from "Tech Support". | SUSPICIOUS |
| 19 | CBI cyber crime alert. Phone illegal activity-la linked. Case agamal irukka fine kudukka. | HIGH_RISK |
| 20 | Netflix subscription confirmed. Action thevai illa. | SAFE |
