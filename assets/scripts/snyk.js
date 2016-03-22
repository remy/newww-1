var snyk = module.exports = function () {
  $(snyk.init);
  return snyk;
};

snyk.api = 'https://snyk.io/api/v1/';

snyk.init = function() {
  snyk.element = $('#snyk_vulns');

  // check that the element includes everything we need to perform the XHR
  // request for vulnerabilities
  if (!snyk.element.length) {
    return;
  }

  var data = snyk.element.data();

  if (!data.name || !data.version) {
    return;
  }

  // kick off XHR requests
  snyk.getVulnerabilities(data);
};

snyk.getVulnerabilities = function (pkg) {
  var root = snyk.api + 'vuln/npm';
  var name = pkg.name;
  var version = pkg.version;

  return $.getJSON(root + '/' + name + '/' + version).done(function (res) {
    var vulns = {
      vulns: 0,
      directVulns: 0,
      depVulns: 0
    };

    if (!res.ok) {
      // I wanted to use .reduce here, but wasn't sure about target support
      // and couldn't find any other use of reduce in the asset/scripts dir
      // so using .forEach (also appears in star.js).
      res.vulnerabilities.forEach(function (curr) {
        vulns.vulns++;

        if (curr.from.length === 1) {
          vulns.directVulns++;
        } else {
          vulns.depVulns++;
        }

        return vulns;
      });
    }

    var label = vulns.depVulns + ' vulnerable ' + pl('dependency', vulns.depVulns);
    if (vulns.vulns === 0) {
      label = 'No known vulnerabilities';
    } else if (vulns.directVulns) {
      label = vulns.directVulns + ' known ' + pl('vulnerability', vulns.directVulns);
    }

    // double check in case we've been called directly
    if (snyk.element.length) {
      snyk.element.find('span').show();
      snyk.element.find('a').text(label);
    } else {
      return label;
    }
  });
};

function pl(word, count) {
  if (count > 1) {
    return word.slice(0, -1) + 'ies';
  }
  return word;
}