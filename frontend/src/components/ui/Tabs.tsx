interface TabsProps {
  tabs: string[]
  activeTab: string
  onTabChange: (tab: string) => void
}

export default function Tabs({ tabs, activeTab, onTabChange }: TabsProps) {
  return (
    <div className="gf-tabs">
      {tabs.map(tab => (
        <button
          key={tab}
          className={`gf-tab ${activeTab === tab ? 'active' : ''}`}
          onClick={() => onTabChange(tab)}
        >
          {tab}
        </button>
      ))}
    </div>
  )
}
