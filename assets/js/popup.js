// Initialize button
const toggleEnableButton = document.getElementById('toggle-enable');
console.log(toggleEnableButton)

// In-page cache of the user's options
const options = {
  enabled: false
};

const updateButtonText = () => {
  toggleEnableButton.innerText = options.enabled ? 'Disable' : 'Enable'
}

toggleEnableButton.addEventListener('click', (event) => {
  options.enabled = !options.enabled
  chrome.storage.sync.set({options});
  updateButtonText()
});

// Initialize the form with the user's option settings
chrome.storage.sync.get("options").then((data) => {
  Object.assign(options, data.options);
  updateButtonText()
});