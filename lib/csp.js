var csp = module.exports = {};

csp.default = {
  defaultSrc: 'self',
  scriptSrc: [
    'self',

    // Hubspot
    'https://forms.hubspot.com/uploads/form/v2/419727/9a2b4ac5-ef09-43e6-854a-d82c92347c9d',
    'https://forms.hubspot.com/uploads/form/v2/419727/6672f0d7-d2df-4696-a164-a8fa139d8f15',
    'https://forms.hubspot.com/uploads/form/v2/419727/64c6e95b-b2c7-4989-a8ae-d967645e5198',
    'https://forms.hubspot.com/uploads/form/v2/419727/d9ba17d5-606e-456d-a703-733c67f5e708',
    'https://js.hsforms.net/forms/current.js',
    'https://api.hubapi.com',
    'https://internal.hubapi.com',
    'https://js.hs-analytics.net',

    // Eloqua
    'https://img.en25.com/i/elqCfg.min.js',

    // Stripe
    'https://api.stripe.com',
    'https://checkout.stripe.com/checkout.js',
    'https://js.stripe.com',

    // Twitter
    'https://platform.twitter.com/oct.js',

    // Google
    'https://www.google-analytics.com',
    'https://fonts.googleapis.com',

    // Mailchimp
    'https://s3.amazonaws.com/downloads.mailchimp.com/js/mc-validate.js',
    'https://npmjs.us9.list-manage.com',

    // HTML5 tag support for old browsers
    'https://cdnjs.cloudflare.com/ajax/libs/html5shiv/3.7.2/html5shiv.min.js',

    // Optimizely
    'https://cdn.optimizely.com/js/3318080746.js',

    // Constructor.io
    'https://cnstrc.com/js/ac.js',
    'https://ac.cnstrc.com',

    // AccountDock
    'https://static.accountdock.com/app.min.js',

    // Marketing Assets
    'https://assets.npmjs.com',
  ],
  styleSrc: [
    'self',
    'unsafe-inline',
    'https://fonts.googleapis.com',
    'https://assets.npmjs.com',
  ],
  imgSrc: '*',
  connectSrc: [
    'self',
    'https://typeahead.npmjs.com/',
    'https://partners.npmjs.com/',
    'https://checkout.stripe.com/api/outer/manhattan',
    'https://snyk.io/api/v1/vuln/npm',
    'https://api.github.com',
    'https://ac.cnstrc.com',
    'https://*.log.optimizely.com',
  ],
  fontSrc: [
    'self',
    'https://fonts.gstatic.com',
    'https://assets.npmjs.com',
  ],
  frameSrc: [
    'https://checkout.stripe.com',
    'https://js.stripe.com',
    'https://www.youtube.com',
    'https://s3-us-west-2.amazonaws.com/files.accountdock.com/pre.prod.html',
    'https://accountdock.com/app',
    'https://assets.npmjs.com',
  ],
  reportUri: '/-/csplog'
};

if (process.env.NODE_ENV === 'dev') {
  csp.default.scriptSrc.push('unsafe-eval');
}
