# Worksheet Desk – improvements

## What changed

- Refreshed both teacher and student pages with a cleaner, more readable, mobile-first layout, softer cards, clearer actions, and improved dark-mode colors.
- Added a server-side Gemini extraction step for PDF text. It is specifically instructed to copy existing questions only, keep the reading passage / 文章 / petikan in its own field, ignore numbered story paragraphs as questions, and avoid inventing extra questions.
- Set the default import limit to **5 questions**, with options for 3, 5, 8, 10, or all detected questions. Choosing “All detected” uses the local PDF reader.
- Added a local-reader fallback when Gemini is not configured, unavailable, or unable to separate the worksheet confidently.
- Improved the fallback parser for Chinese, English, and Bahasa Melayu question numbering and numbered article paragraphs.
- Added **Move to 文章** to each item in the review screen, so a paragraph that was mistakenly detected as a question can be moved into the passage editor with one tap.
- Added Chinese as a worksheet display language, so Chinese reading passages and submit controls render more appropriately for students.
- The Gemini API key stays on the server and is never sent to the browser.

## Important

PDF layouts and OCR quality vary, especially for scanned worksheets. Always review the passage and questions before publishing. If Gemini is unavailable, the local reader will be used and its results may need more manual correction.

## Deployment

Keep the existing project structure when uploading these files to the existing GitHub/Vercel project. The `api/server.js` change accepts Chinese (`zh`) worksheets and adds the teacher-only `extractWorksheet` endpoint. Existing Supabase tables and environment variables do not need a schema change. The AI separation feature uses the existing `GEMINI_API_KEY` and optional `GEMINI_MODEL` Vercel environment variables.


## Remembered sign-in

- Student and teacher sign-in is saved in browser `localStorage`, so it survives closing and reopening the site/browser.
- Closing the browser or being inactive no longer signs users out automatically.
- The explicit **Sign out** action clears the saved token and user data. A sign-out in another tab is also respected.
- The API issues 30-day tokens and renews them when the signed-in page is reopened or revisited. A user who stays away longer than the token lifetime may need to sign in again.
- Sign-in is saved per device/browser. On shared devices, choose **Sign out** when finished.
