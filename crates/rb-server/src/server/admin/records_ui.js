import { $, state } from "./state.js";
import {
  bindRecordBrowserControls,
  bindRecordNoCollectionControls,
  recordNoCollectionHtml,
  recordsBrowserHtml
} from "./records/browser.js";
import {
  bindRecordEditorControls,
  closeRecordEditor,
  recordEditorHtml
} from "./records/editor.js";
import { ensureRelationOptionsForCollection } from "./records/relations.js";

let actions = {
  currentCollection: () => null,
  render() {},
  loadRecords: async () => {},
  resetRecordBrowser() {},
  setView: async () => {}
};

export { closeRecordEditor, ensureRelationOptionsForCollection };

export function renderRecords(nextActions) {
  actions = nextActions;
  const collection = actions.currentCollection();
  if (!state.token) {
    $("content").innerHTML = `
      <div class="empty">
        <strong>Login or initialize first</strong>
        <span>Records are available after a superuser session is active.</span>
      </div>
    `;
    return;
  }

  if (!collection) {
    $("content").innerHTML = recordNoCollectionHtml();
    bindRecordNoCollectionControls(actions);
    return;
  }

  $("content").innerHTML = `
    ${recordsBrowserHtml(collection)}
    ${recordEditorHtml(actions)}
  `;
  bindRecordBrowserControls(actions);
  bindRecordEditorControls(actions);
}
