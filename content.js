/**
 * Store mail names as constants
 */
const MAIL_NAMES = {
  GOOGLE: 'GOOGLE'
}

/**
 * Mail pages where emails should be checked
 * @type {[{name: string, url: string}]}
 */
const MAIL_PAGES = [
  {
    name: MAIL_NAMES.GOOGLE,
    url: 'https://mail.google.com/mail/u/0/'
  }
]



/**
 * Listen for messages sent from background.js
 */
chrome.runtime.onMessage.addListener(
  function (request, sender, sendResponse) {
    if (request.message === 'tab_updated') {
      checkPhishing()
    }
  });

const checkPhishing = () => {
  const page = getMailPage()
  // do nothing if page is not one of supported mail pages
  if(!page) {
    return
  }

  switch (page) {
    case MAIL_NAMES.GOOGLE:
      checkGmail()
  }
}

/**
 * Check if email content is open
 * @returns {boolean}
 */
const checkMailPageView = () => {
  const regex = /https:\/\/mail\.google\.com\/mail\/u\/0\/#(\w+([a-zA-Z]?\w+))\/(\w+([\.-]?\w+))/gm
  return regex.test(location.href)
}

/**
 * Check if original mail page is open
 * @returns {boolean}
 */
const checkOriginalMailPageView = () => {
  const regex = /view=om/gm
  return regex.test(location.search)
}

const getDialog = async () => {
  let dialog = document.getElementById("phishing-detector-dialog")
  if(!dialog) {
    const dialogResponse = await fetch(chrome.runtime.getURL('modals/dialog.html'))
    dialog = await dialogResponse.text()
  } else {
    dialog = dialog.outerHTML
  }

  const wrapper = document.createElement('div')
  wrapper.innerHTML = dialog

  return wrapper.firstChild
}
const loadModalContent = async (url) => {

  const dialog = await getDialog()
  const response = await fetch(chrome.runtime.getURL('modals/' + url))
  if(!response.ok) {
    return ''
  }

  dialog.querySelector('div[id="dialog-content"]').innerHTML = await response.text()

  return dialog
}

const showOriginalMailRequiredDialog = async () => {
  const dialog = await loadModalContent('original_mail_required.html')
  document.body.appendChild(dialog);
  dialog.showModal();

  dialog.querySelector("button").addEventListener("click", () => {
    dialog.close();
  });
}
/**
 * Check gmail page for phishing email
 */
const checkGmail = () => {
  const isMailPageView = checkMailPageView()
  const isOriginalMailPageView = checkOriginalMailPageView()

  if (isMailPageView) {
    return showOriginalMailRequiredDialog()
  }

  if(isOriginalMailPageView) {
    // todo implement email content parsing and alerts
    console.log("checking email")
  }
}

/**
 * Return mail page name if on supported mail tab
 * @returns {string|null}
 */
const getMailPage = () => {
  for (const {name, url} of MAIL_PAGES) {
    if (location.href.startsWith(url)) {
      return name
    }
  }

  return null
}

const collectFeatures = () => {

}

const checkEmail =  async (page) => {
  console.log(page, document.body)

  const features = collectFeatures()

  const response = await fetch("http://localhost:5680")
  console.log(response)
  // response.result
}
