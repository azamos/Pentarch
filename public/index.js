const handleClick = (e = "asfasf") => {
  // console.log("Pressed a button!", e.target);
  addFakeItem();
};

const generateItem = ({ title, definition, severity, assignee }) => {
  const item = document.createElement("div");
  item.className = "Item Flex-Col Centered";
  const titleDiv = document.createElement("div");
  titleDiv.className = "SideTitle";
  titleDiv.innerText = title;
  const definitionDiv = document.createElement("div");
  definitionDiv.className = "Definition";
  definitionDiv.innerText = definition;
  const serverityDiv = document.createElement("div");
  serverityDiv.className = "Severity";
  serverityDiv.innerText = severity;
  const assigneeDiv = document.createElement("div");
  assigneeDiv.className = "Assignee";
  assigneeDiv.innerText = assignee;
  item.appendChild(titleDiv);
  item.appendChild(definitionDiv);
  item.appendChild(serverityDiv);
  item.appendChild(assigneeDiv);
  return item;
};

const addItem = (data) => {
  const item = generateItem(data);
  document.getElementById("container").appendChild(item);
};

const addFakeItem = () =>
  addItem({
    title: "test",
    definition: "test def",
    severity: "LOW",
    assignee: "Amos",
  });
