chrome.runtime.onInstalled.addListener(() => {
  console.log('Extension is initialized');
});

// Add a listener for when a tab is updated
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Check if the URL of the tab matches a specific pattern
  // console.log('Tab URL matches the pattern:', tab.url);
  // console.log(changeInfo, tab)
  if (changeInfo.status === 'complete') {
    chrome.tabs.sendMessage( tabId, {
      message: 'check update',
      changeInfo
    })
  }
});