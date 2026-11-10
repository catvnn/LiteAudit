chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  if (/\.(txt|csv)$/i.test(item.filename)) {
    suggest({ filename: "quarantine/" + item.filename, conflictAction: "uniquify" });
  }
});
