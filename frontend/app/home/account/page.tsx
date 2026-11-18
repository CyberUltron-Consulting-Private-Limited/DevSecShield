// Account outside a team (#14): the /home user menu opens this, the team Account page (app/[team_id]/account) inside
// the /home layout, so a user without a team can change their password too.
import AccountPage from "@/app/[team_id]/account/page";

export default function HomeAccountPage() {
  return <AccountPage />;
}
