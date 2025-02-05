import { useState, useEffect } from 'react';
import { useSelector } from 'react-redux';

export default function ResizeableText(
  {
    value,
    readOnly,
    id = undefined,
    onKeyDown = _ => undefined,
    dummy,
    setValue = _ => undefined,
  }: {
    value: string,
    readOnly: boolean,
    id?: string,
    onKeyDown?: (e: any) => void,
    dummy: any,
    setValue?: (e: string) => void,
  },
) {
  const [height, setHeight] = useState(24);
  const bigTextBoxes = useSelector((state: any) => state.bigTextBoxes);
  const handleChange = (event: any) => {
    setValue(event.target.value);
    if (dummy.current) {
      dummy.current.value = event.target.value;
      setHeight(dummy.current.scrollHeight);
      dummy.current.value = '';
    }
  };
  const resize = () => {
    if (dummy.current) {
      dummy.current.value = value;
      setHeight(dummy.current.scrollHeight);
      dummy.current.value = '';
    }
  };
  useEffect(resize, [value]);
  const tabBehaviour = useSelector((state: any) => state.tabBehaviour);
  const handleKeyDown = (event: any) => {
    if (!readOnly && !event.metaKey && !event.altKey && !event.ctrlKey && tabBehaviour === 'insert' && event.key === 'Tab') {
      event.preventDefault();
      const start = event.target.selectionStart;
      const end = event.target.selectionEnd;
      const newValue = value.slice(0, start) + '\t' + value.slice(end);
      event.target.value = newValue;
      event.target.selectionStart = start + 1;
      event.target.selectionEnd = start + 1;
      handleChange(event);
    }
    else {
      onKeyDown(event);
    }
  }
  return (
    <>
      <textarea
        id={id}
        value={value}
        readOnly={readOnly}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        style={{ height: `max(${height + 2 * 8}px, ${(bigTextBoxes ? 3 : 1) * 24 + 2 * 8}px)` }}
        className="block w-full my-4 p-2 rounded bg-gray-100 dark:bg-gray-800 font-mono text-base resize-none cursor-text focus:outline-none focus:ring transition"
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="none"
        spellCheck={false}
      />
    </>
  );
}
