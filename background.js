const ICONS = {
  ENABLED: './assets/img/enabled.png',
  DISABLED: './assets/img/disabled.png'
}

chrome.runtime.onInstalled.addListener(() => {
  console.log('Extension is initialized');
  chrome.storage.sync.set({options: {
    enabled: false
    }
  });
});

// Add a listener for when a tab is updated
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    chrome.tabs.sendMessage( tabId, {
      message: 'tab_updated'
    })
  }
});

chrome.storage.sync.get('enabled', (data) => {
  setIcon(data.enabled)
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'sync') return

  const { enabled } = changes.options.newValue
  setIcon(enabled)
});

const setIcon = (enabled) => {
  const path = enabled ? ICONS.ENABLED : ICONS.DISABLED
  chrome.action.setIcon({ path });
}