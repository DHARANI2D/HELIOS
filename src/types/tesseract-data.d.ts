// @tesseract.js-data/eng ships CommonJS without types: where its trained
// data lives, for createWorker's langPath.
declare module "@tesseract.js-data/eng" {
  const data: { code: string; gzip: boolean; langPath: string };
  export default data;
}
