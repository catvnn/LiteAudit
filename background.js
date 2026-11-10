chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  suggest({ filename: "LiteAudit_Quarantine/" + item.filename, conflictAction: "uniquify" });
});
