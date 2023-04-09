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
 * Norton revealed top malicious urls
 * @type {string[]}
 */
const MALICIOUS_URLS = [
  '17ebook.com',
  'aladel.net',
  'bpwhamburgorchardpark.org',
  'clicnews.com',
  'dfwdiesel.net',
  'divineenterprises.net',
  'fantasticfilms.ru',
  'gardensrestaurantandcatering.com',
  'ginedis.com',
  'gncr.org',
  'hdvideoforums.org',
  'hihanin.com',
  'kingfamilyphotoalbum.com',
  'likaraoke.com',
  'mactep.org',
  'magic4you.nu',
  'marbling.pe.kr',
  'nacjalneg.info',
  'pronline.ru',
  'purplehoodie.com',
  'qsng.cn',
  'seksburada.net',
  'sportsmansclub.net',
  'stock888.cn',
  'tathli.com',
  'teamclouds.com',
  'texaswhitetailfever.com',
  'wadefamilytree.org',
  'xnescat.info',
  'yt118.com'
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
    const raw = document.getElementsByTagName('pre')[0].textContent
    return checkEmail(raw)
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

const collectFeatures = (raw) => {
  const message = getPlainMessage(raw).toLowerCase()
  const urls = getUrls(message)
  const {domains, malicious_urls, ip_urls, hex_urls, mailto, dots_count, text_link_disparity} = getUrlsInfo(urls)

  const features = {
    re_mail: isReMail(raw),
    body_richness: getEmailBodyRichness(message),
    general_salutation: isGeneralSalutation(message),
    contains_prime_targets: getContainsPrimeTargets(message),
    attachments: getAttachmentsCount(message),
    HTML: isHtml(raw),
    contains_account: message.includes('account'),
    contains_update: message.includes('update'),
    contains_access: message.includes('access'),
    urls: urls.length,
    domains,
    malicious_urls,
    ip_urls,
    hex_urls,
    mailto,
    dots_count,
    text_link_disparity
  }

  return convertBooleanValues(features)
}

const checkEmail =  async (raw) => {
  const features = collectFeatures(raw)
  const params = new URLSearchParams(features).toString()
  // todo change url and method
  let response = await fetch('http://localhost:5000?' + params);
  response = await response.json()

  // todo show modal with response
  console.log('response', response.predict)
  console.log('features', features)
}





/*******************************
 * Helpers
 *******************************/


/**
 * Cut message part from raw text
 *
 * @param raw
 * @returns {*}
 */
const getMessageFromRawEmail = (raw) => {
  let message = raw.slice(raw.indexOf('Content-Type: text/html;'))
  message = message.slice(message.indexOf('<'), message.lastIndexOf('>') + 1)
  return message
}

/**
 * Parse plain text message
 *
 * @param raw
 */
const getPlainMessage = (raw) => {
  let message = raw.slice(raw.indexOf('Content-Type: text/plain;'), raw.indexOf('Content-Type: text/html;'))
  message = message.slice(message.indexOf('\n'), message.lastIndexOf('--'))
  // gmail cuts long lines with = sign and puts the remaining to the next line, so replace them too
  message = message.replaceAll('=\n', '')
  return message
}

/**
 * message param is passed with html tags, but not to confuse with signed messages,
 * only consider that message is html if it was sent as whole html content
 *
 * @param raw
 * @returns {boolean}
 */
const isHtml = (raw) => {
  return getMessageFromRawEmail(raw).startsWith('<!')
}

/**
 *
 * @param message
 * @returns {*}
 */
const getUrls = (message) => {
  const regex = /\[([^\[]+)\](\(.*\))/gm
  return message.match(regex) || []
}

/**
 * Collect bulk data from urls
 *
 * @param urls
 * @returns {{ip_urls: number, domains: number, mailto: boolean, malicious_urls: number, hex_urls: number}}
 */
const getUrlsInfo = (urls) => {
  const domains_set = new Set()
  let malicious_urls = 0
  let ip_urls = 0
  let hex_urls = 0
  let dots_count = 0
  let mailto = false
  let text_link_disparity = false

  for (const mdUrl of urls) {
    const url = mdUrl.slice(mdUrl.indexOf('//') + 2) // cat after //
    const domain = url.slice(0, url.indexOf('/'))
    domains_set.add(domain)

    if(MALICIOUS_URLS.includes('domain')) {
      malicious_urls++
    }

    if(isIpV4(domain)) {
      ip_urls++
    }

    if (url.includes('%')) {
      hex_urls++
    }

    if(url.includes('mailto')) {
      mailto = true
    }

    dots_count += url.match(/\./g).length

    // check if text and url are the same
    const splitUrl = mdUrl.slice(1, mdUrl.length - 1).split('](')
    if(!text_link_disparity) {
      text_link_disparity = splitUrl[0] === splitUrl[1]
    }
  }

  return {
    domains: domains_set.size,
    malicious_urls,
    ip_urls,
    hex_urls,
    mailto,
    dots_count,
    text_link_disparity
  }
}

const isIpV4 = (domain) => {
  const blocks = domain.split(".");
  if(blocks.length === 4) {
    return blocks.every(block => {
      const num = parseInt(block,10)
      return num >=0 && num <= 255;
    });
  }
  return false;
}

const isGeneralSalutation = (message) => {
  return message.slice(0, 50).includes('dear')
}

const getAttachmentsCount = (message) => {
  const matches = message.match('Content-Disposition: attachment;')
  return matches ? matches.length : 0
}

const getEmailBodyRichness = (message) => {
  return message.length / 1000
}

const getContainsPrimeTargets = (message) => {
  // todo add more in the future
  const targetPhrases = [
    'your bank', 'cvv', 'cv2', 'credit card', 'expired', 'winner', 'bet', 'cash', 'urgent', 'transaction', 'hurry'
  ]

  for (const str of targetPhrases) {
    if (message.includes(str)) {
      return true
    }
  }

  return false
}

const isReMail = () => {
  const tbody = document.querySelector('tbody')
  const subject = tbody.children[4].querySelector('td').textContent

  return subject.toLowerCase().startsWith('re:')
}

const convertBooleanValues = (object) => {
  for(const prop in object) {
    if (typeof object[prop] === 'boolean') {
      object[prop] = Number(object[prop])
    }
  }

  return object
}