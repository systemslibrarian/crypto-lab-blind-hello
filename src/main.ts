import './styles.css';
import { introPanel } from './ui/intro';
import { observerPanel } from './ui/observerpanel';
import { innerOuterPanel } from './ui/innerouter';
import { dnsPanel } from './ui/dnspanel';
import { breakItPanel } from './ui/breakit';
import { trustPanel } from './ui/trustpanel';
import { greasePanel } from './ui/grease';
import { deploymentPanel } from './ui/deployment';

const app = document.getElementById('app');
if (!app) throw new Error('#app mount point missing');

const main = document.createElement('main');
main.className = 'lab-main';
main.append(
  introPanel(),
  observerPanel(),
  innerOuterPanel(),
  dnsPanel(),
  breakItPanel(),
  trustPanel(),
  greasePanel(),
  deploymentPanel(),
);
app.append(main);
