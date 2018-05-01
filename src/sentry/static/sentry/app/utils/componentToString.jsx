import ReactDOM from 'react-dom';

export default function componentToString(node) {
  let el = document.createElement('div');
  ReactDOM.render(node, el);
  return el.innerHTML;
}
