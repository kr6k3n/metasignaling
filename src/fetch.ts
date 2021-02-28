let fetch = null;
const browser = typeof window !== "undefined";
export default fetch = browser ?
                       window.fetch :
                       require("node-fetch");
