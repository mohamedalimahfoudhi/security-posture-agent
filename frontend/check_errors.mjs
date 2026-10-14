import puppeteer from 'puppeteer';

(async () => {
  const browser = await puppeteer.launch({ headless: 'new' });
  const page = await browser.newPage();
  
  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  page.on('pageerror', error => console.log('PAGE ERROR:', error.message));
  page.on('response', response => {
    if (!response.ok()) {
      console.log('API FAILURE:', response.url(), response.status());
    }
  });

  try {
    console.log('--- Visiting /alerts ---');
    await page.goto('http://localhost:5173/alerts', { waitUntil: 'networkidle2', timeout: 10000 });
  } catch (e) {
    console.log('Goto Error:', e);
  }

  try {
    console.log('--- Visiting /third-parties ---');
    await page.goto('http://localhost:5173/third-parties', { waitUntil: 'networkidle2', timeout: 10000 });
  } catch (e) {
    console.log('Goto Error:', e);
  }

  await browser.close();
})();
