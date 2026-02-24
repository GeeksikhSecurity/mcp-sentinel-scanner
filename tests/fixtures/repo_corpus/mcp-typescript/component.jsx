export function Component({ userInput }) {
  return <div dangerouslySetInnerHTML={{ __html: userInput }} />;
}


