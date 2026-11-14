// Quantum risk grade (CB-19) and crypto-agility fix class (CB-24): one module to import from.
//
// Mount contract (any page; the Sources run results UI and CB-38's run results page use the same components):
//   * every component takes the API's own objects; none fetches run data. `teamId` is used only to fetch the two
//     model routes (grade-model, agility-model), cached under ["cbom-sources", teamId, …]; pass `model` instead to
//     fetch nothing (tests, or a page that already loaded the model);
//   * every component renders nothing (or "—") when its fields are absent, so an older backend never crashes a page;
//   * unseen values (a future grade or class) are printed as they came and marked, never thrown on.
//
//   run asset list item  -> <QGradeChip item={item} assetId={item.id} />        hook run-asset-q-<id>, data-q
//                           <FixClassChip item={item} assetId={item.id} />      hook run-asset-fixclass-<id>, data-fix-class
//   asset detail         -> <QGradeDrawerSection teamId={t} asset={detail} />    reads q_grade, q_reason, q_explain
//                           <AgilityDrawerSection teamId={t} agility={detail.agility} />
//   run posture          -> <QDistributionCard teamId={t} posture={posture} onOpenAsset={(id) => …} />
//                              hooks posture-q-<grade key or none> (data-count), q0-item-<key> (data-reason)
//                           <AgilityPostureCard teamId={t} posture={posture} />  hooks posture-fix-<value> (data-count)
//   CBOM team page      -> <AgilityBaselineSection teamId={t} />  (CB-25: GET /{team}/cbom/agility + /subjects drill-down)
//                              hooks agility-baseline (data-assets), agility-baseline-system-<key>-<value> (data-count)
//   anywhere             -> <Q0ItemList items={posture.q0_items} total={posture.q0_items_total} />,
//                           <QGradeModelDialog teamId={t} open onOpenChange />, <AgilityDistribution posture={posture} />
//
// RunPosture.tsx mounts the two posture cards inside RunPostureCard and the two drawer sections inside
// AssetDetailPanel, so any page that already mounts those two gets them with no change.
export { GradeInputsBanner, QDistributionBar, QDistributionCard, QGradeChip, QGradeDrawerSection, QGradeModelBody, QGradeModelDialog, Q0ItemList } from "./QGrade";
export { AgilityDistribution, AgilityDrawerSection, AgilityPostureCard, EvidenceFixClass, FixClassChip } from "./Agility";
export { AgilityBaselineSection, AgilityBaselineView, AgilitySubjectsTable, AgilitySystemsTable, type DrillDown } from "./AgilityBaseline";
export * from "./baseline";
export { Tip } from "./Tip";
export { GRADE_TIPS, fixClassTipId, type GradeTipId, type TipEntry } from "./tips";
export { gradeKeys, getCbomAgilityBaseline, getCbomAgilityModel, getCbomAgilitySubjects, getCbomGradeModel, useAgilityModel, useGradeModel } from "./api";
export * from "./model";
export * from "./inputs";
