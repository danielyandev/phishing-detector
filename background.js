chrome.runtime.onInstalled.addListener(() => {
  console.log('Extension is initialized');
});

// Add a listener for when a tab is updated
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    chrome.tabs.sendMessage( tabId, {
      message: 'tab_updated'
    })
  }
});