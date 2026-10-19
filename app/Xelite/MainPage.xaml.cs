using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Windows.ApplicationModel;
using Windows.ApplicationModel.DataTransfer;
using Windows.Networking.Vpn;
using Windows.UI;
using Windows.UI.Popups;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Xelite.Core;

namespace Xelite
{
    public sealed partial class MainPage : Page
    {
        private static readonly Brush ConnectedBrush = new SolidColorBrush(Color.FromArgb(0xFF, 0x33, 0x99, 0x33));

        private readonly ObservableCollection<ServerItem> _servers = new ObservableCollection<ServerItem>();
        private readonly ObservableCollection<SubscriptionItem> _subscriptions = new ObservableCollection<SubscriptionItem>();
        private readonly DispatcherTimer _statusTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        private List<Subscription> _model = new List<Subscription>();
        private VpnManagementConnectionStatus _status = VpnManagementConnectionStatus.Disconnected;
        private Brush _accentBrush;
        private bool _loadingSettings;

        public MainPage()
        {
            InitializeComponent();
            ServerList.ItemsSource = _servers;
            SubscriptionList.ItemsSource = _subscriptions;
            _statusTimer.Tick += async (s, e) => await RefreshStatusAsync();
            Loaded += MainPage_Loaded;
        }

        private async void MainPage_Loaded(object sender, RoutedEventArgs e)
        {
            _accentBrush = ConnectButton.Background;
            LoadSettings();
            var v = Package.Current.Id.Version;
            AboutText.Text = string.Format("Xelite {0}.{1}.{2}\nXray-core v26.2.6 for Windows 10 Mobile", v.Major, v.Minor, v.Build);

            _model = await SubscriptionStore.LoadAsync();
            Rebuild();
            _statusTimer.Start();
            await RefreshStatusAsync();

            if (AppSettings.Current.UpdateOnStart && _model.Any(s => !s.IsManual))
            {
                await UpdateSubscriptionsAsync(_model.Where(s => !s.IsManual).ToList(), quiet: true);
            }
        }

        // ---------- servers ----------

        /// <summary>
        /// Rebuilds the lists. Every subscription with two or more servers gets an
        /// "auto" entry first, which lets Xray's balancer pick among its servers.
        /// </summary>
        private void Rebuild()
        {
            var selected = AppSettings.Current.SelectedLink;
            _servers.Clear();
            foreach (var sub in _model)
            {
                var links = new List<ProxyLink>();
                foreach (var raw in sub.Links)
                {
                    ProxyLink link;
                    if (ProxyLink.TryParse(raw, out link))
                    {
                        links.Add(link);
                    }
                }
                if (links.Count >= 2)
                {
                    var auto = new ServerItem(sub, links);
                    auto.IsSelected = auto.Key == selected;
                    _servers.Add(auto);
                }
                foreach (var link in links)
                {
                    _servers.Add(new ServerItem(link, sub) { IsSelected = link.Raw == selected });
                }
            }
            if (!_servers.Any(s => s.IsSelected) && _servers.Count > 0)
            {
                _servers[0].IsSelected = true;
                AppSettings.Current.SelectedLink = _servers[0].Key;
            }

            _subscriptions.Clear();
            foreach (var sub in _model)
            {
                _subscriptions.Add(new SubscriptionItem(sub));
            }
            EmptyHint.Visibility = _servers.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            UpdateHome();
        }

        private ServerItem Selected => _servers.FirstOrDefault(s => s.IsSelected);

        private void UpdateHome()
        {
            var selected = Selected;
            SelectedText.Text = selected == null ? "no server selected" : selected.Name;
            ServerCountText.Text = _servers.Count(s => !s.IsAuto).ToString();
            ModeText.Text = selected == null ? "" : selected.IsAuto ? "auto · " + (AppSettings.Current.BalancerStrategy == "leastLoad" ? "least load" : "least ping") : selected.Link.Protocol;

            var sub = selected?.Owner;
            TrafficText.Text = sub == null || sub.IsManual ? "" : sub.Name + "\n" + sub.Summary;
        }

        private async void ServerList_ItemClick(object sender, ItemClickEventArgs e)
        {
            var item = (ServerItem)e.ClickedItem;
            if (item.IsSelected)
            {
                return;
            }
            foreach (var s in _servers)
            {
                s.IsSelected = s == item;
            }
            AppSettings.Current.SelectedLink = item.Key;
            UpdateHome();

            // Switching servers while connected: reconnect with the new one.
            if (_status == VpnManagementConnectionStatus.Connected)
            {
                await RunBusyAsync(async () =>
                {
                    await VpnService.DisconnectAsync();
                    await WaitForStatusAsync(VpnManagementConnectionStatus.Disconnected, 5);
                    await VpnService.ConnectAsync(item.Links);
                });
            }
        }

        private void ServerItem_Holding(object sender, HoldingRoutedEventArgs e)
        {
            if (e.HoldingState == Windows.UI.Input.HoldingState.Started)
            {
                ShowServerMenu((FrameworkElement)sender);
            }
        }

        private void ServerItem_RightTapped(object sender, RightTappedRoutedEventArgs e)
        {
            ShowServerMenu((FrameworkElement)sender);
        }

        private void ShowServerMenu(FrameworkElement element)
        {
            var item = (ServerItem)element.DataContext;
            if (item.IsAuto)
            {
                return;
            }
            var menu = new MenuFlyout();
            var copy = new MenuFlyoutItem { Text = "copy link" };
            copy.Click += (s, e) =>
            {
                var data = new DataPackage();
                data.SetText(item.Link.Raw);
                Clipboard.SetContent(data);
            };
            menu.Items.Add(copy);
            if (item.Owner.IsManual)
            {
                var delete = new MenuFlyoutItem { Text = "delete" };
                delete.Click += async (s, e) =>
                {
                    item.Owner.Links.Remove(item.Link.Raw);
                    await SaveAndRebuildAsync();
                };
                menu.Items.Add(delete);
            }
            menu.ShowAt(element);
        }

        private async void Ping_Click(object sender, RoutedEventArgs e)
        {
            if (_status != VpnManagementConnectionStatus.Disconnected)
            {
                // Through the tunnel every TCP connect is answered locally, so results would be meaningless.
                await ShowMessageAsync("disconnect first to measure server latency.");
                return;
            }
            MainPivot.SelectedIndex = 1;
            var items = _servers.Where(i => !i.IsAuto).ToList();
            foreach (var item in items)
            {
                item.Ping = item.Link.Protocol == "hysteria2" ? "udp" : "…";
            }
            var throttle = new System.Threading.SemaphoreSlim(8);
            await Task.WhenAll(items.Where(i => i.Link.Protocol != "hysteria2").Select(async item =>
            {
                await throttle.WaitAsync();
                try
                {
                    var ms = await VpnService.PingAsync(item.Link);
                    item.Ping = ms < 0 ? "timeout" : ms + " ms";
                }
                finally
                {
                    throttle.Release();
                }
            }));
        }

        // ---------- connect ----------

        private async void Connect_Click(object sender, RoutedEventArgs e)
        {
            if (_status == VpnManagementConnectionStatus.Connected || _status == VpnManagementConnectionStatus.Connecting)
            {
                await RunBusyAsync(VpnService.DisconnectAsync);
                return;
            }
            var server = Selected;
            if (server == null)
            {
                await ShowMessageAsync("add a subscription or a server first.");
                return;
            }
            await RunBusyAsync(() => VpnService.ConnectAsync(server.Links));
        }

        private async Task RefreshStatusAsync()
        {
            try
            {
                _status = await VpnService.GetStatusAsync();
            }
            catch (Exception)
            {
                _status = VpnManagementConnectionStatus.Disconnected;
            }
            var connected = _status == VpnManagementConnectionStatus.Connected;
            switch (_status)
            {
                case VpnManagementConnectionStatus.Connected:
                    StatusText.Text = "connected";
                    break;
                case VpnManagementConnectionStatus.Connecting:
                    StatusText.Text = "connecting";
                    break;
                case VpnManagementConnectionStatus.Disconnecting:
                    StatusText.Text = "disconnecting";
                    break;
                default:
                    StatusText.Text = "disconnected";
                    break;
            }
            ConnectLabel.Text = connected || _status == VpnManagementConnectionStatus.Connecting ? "disconnect" : "connect";
            ConnectButton.Background = connected ? ConnectedBrush : _accentBrush;
        }

        private async Task WaitForStatusAsync(VpnManagementConnectionStatus wanted, int seconds)
        {
            for (var i = 0; i < seconds * 4; i++)
            {
                if (await VpnService.GetStatusAsync() == wanted)
                {
                    return;
                }
                await Task.Delay(250);
            }
        }

        // ---------- subscriptions ----------

        private async void AddSubscription_Click(object sender, RoutedEventArgs e)
        {
            var url = new TextBox { Header = "subscription URL", InputScope = UrlScope(), PlaceholderText = "https://" };
            var name = new TextBox { Header = "name (optional)", Margin = new Thickness(0, 12, 0, 0) };
            var dialog = new ContentDialog
            {
                Title = "add subscription",
                Content = new StackPanel { Children = { url, name } },
                PrimaryButtonText = "add",
                SecondaryButtonText = "cancel",
            };
            if (await dialog.ShowAsync() != ContentDialogResult.Primary)
            {
                return;
            }
            var subUrl = Subscription.UnwrapImportLink(url.Text);
            if (subUrl == null)
            {
                await ShowMessageAsync("that is not a valid subscription URL.");
                return;
            }
            await AddSubscriptionAsync(subUrl, name.Text.Trim());
        }

        private async Task AddSubscriptionAsync(string url, string name)
        {
            var existing = _model.FirstOrDefault(s => s.Url == url);
            if (existing != null)
            {
                await UpdateSubscriptionsAsync(new List<Subscription> { existing }, quiet: false);
                return;
            }
            var sub = new Subscription { Url = url, Name = name };
            _model.Insert(_model.Count - 1, sub);
            await UpdateSubscriptionsAsync(new List<Subscription> { sub }, quiet: false);
            MainPivot.SelectedIndex = 1;
        }

        private async void Paste_Click(object sender, RoutedEventArgs e)
        {
            string text;
            try
            {
                text = (await Clipboard.GetContent().GetTextAsync()).Trim();
            }
            catch (Exception)
            {
                await ShowMessageAsync("the clipboard does not contain text.");
                return;
            }
            if (text.StartsWith("happ://crypt", StringComparison.OrdinalIgnoreCase))
            {
                await ShowMessageAsync("happ://crypt links are encrypted with Happ's private key and only open in Happ. " +
                                       "ask your provider for the plain https:// subscription link.");
                return;
            }

            var links = Subscription.ExtractLinks(text);
            if (links.Count > 0)
            {
                var manual = _model.First(s => s.IsManual);
                manual.Links.AddRange(links.Where(l => !manual.Links.Contains(l)));
                await SaveAndRebuildAsync();
                MainPivot.SelectedIndex = 1;
                return;
            }
            var subUrl = Subscription.UnwrapImportLink(text);
            if (subUrl != null)
            {
                await AddSubscriptionAsync(subUrl, "");
                return;
            }
            await ShowMessageAsync("no subscription URL or supported link found in the clipboard.");
        }

        private async void UpdateAll_Click(object sender, RoutedEventArgs e)
        {
            await UpdateSubscriptionsAsync(_model.Where(s => !s.IsManual).ToList(), quiet: false);
        }

        private async Task UpdateSubscriptionsAsync(List<Subscription> subs, bool quiet)
        {
            var errors = new List<string>();
            Busy.Visibility = Visibility.Visible;
            try
            {
                foreach (var sub in subs)
                {
                    try
                    {
                        await sub.UpdateAsync();
                    }
                    catch (Exception ex)
                    {
                        errors.Add((string.IsNullOrEmpty(sub.Name) ? sub.Url : sub.Name) + ": " + ex.Message);
                        if (sub.Links.Count == 0 && string.IsNullOrEmpty(sub.Name))
                        {
                            _model.Remove(sub);
                        }
                    }
                }
                await SaveAndRebuildAsync();
            }
            finally
            {
                Busy.Visibility = Visibility.Collapsed;
            }
            if (errors.Count > 0 && !quiet)
            {
                await ShowMessageAsync(string.Join("\n", errors));
            }
        }

        private async void SubscriptionList_ItemClick(object sender, ItemClickEventArgs e)
        {
            var sub = ((SubscriptionItem)e.ClickedItem).Model;
            if (sub.IsManual)
            {
                return;
            }
            // MessageDialog is limited to two commands on phones, so use a ContentDialog.
            var dialog = new ContentDialog
            {
                Title = sub.Name,
                Content = new TextBlock { Text = sub.Url, TextWrapping = TextWrapping.Wrap, Opacity = 0.7 },
                PrimaryButtonText = "update",
                SecondaryButtonText = "delete",
                CloseButtonText = "cancel",
            };
            var choice = await dialog.ShowAsync();
            if (choice == ContentDialogResult.Primary)
            {
                await UpdateSubscriptionsAsync(new List<Subscription> { sub }, quiet: false);
            }
            else if (choice == ContentDialogResult.Secondary)
            {
                _model.Remove(sub);
                await SaveAndRebuildAsync();
            }
        }

        private async Task SaveAndRebuildAsync()
        {
            await SubscriptionStore.SaveAsync(_model);
            Rebuild();
        }

        // ---------- settings ----------

        private void LoadSettings()
        {
            _loadingSettings = true;
            var s = AppSettings.Current;
            BalancerBox.SelectedIndex = s.BalancerStrategy == "leastLoad" ? 1 : 0;
            DnsBox.Text = string.Join(", ", s.DnsServers);
            BypassLanSwitch.IsOn = s.BypassLan;
            BlockQuicSwitch.IsOn = s.BlockQuic;
            UpdateOnStartSwitch.IsOn = s.UpdateOnStart;
            MtuBox.Text = s.Mtu.ToString();
            UserAgentBox.Text = s.UserAgent;
            LogLevelBox.SelectedItem = s.LogLevel;
            _loadingSettings = false;
        }

        private void Settings_Changed(object sender, RoutedEventArgs e)
        {
            if (_loadingSettings)
            {
                return;
            }
            var s = AppSettings.Current;
            var balancer = (BalancerBox.SelectedItem as ComboBoxItem)?.Tag as string;
            if (balancer != null && balancer != s.BalancerStrategy)
            {
                s.BalancerStrategy = balancer;
                foreach (var item in _servers.Where(i => i.IsAuto))
                {
                    item.RefreshDetail();
                }
                UpdateHome();
            }
            var dns = DnsBox.Text.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(ConfigBuilder.IsIp).ToArray();
            if (dns.Length > 0)
            {
                s.DnsServers = dns;
            }
            s.BypassLan = BypassLanSwitch.IsOn;
            s.BlockQuic = BlockQuicSwitch.IsOn;
            s.UpdateOnStart = UpdateOnStartSwitch.IsOn;
            int mtu;
            if (int.TryParse(MtuBox.Text, out mtu) && mtu >= 576 && mtu <= 9000)
            {
                s.Mtu = mtu;
            }
            if (!string.IsNullOrWhiteSpace(UserAgentBox.Text))
            {
                s.UserAgent = UserAgentBox.Text.Trim();
            }
            if (LogLevelBox.SelectedItem is string level)
            {
                s.LogLevel = level;
            }
        }

        private async void ShowLog_Click(object sender, RoutedEventArgs e)
        {
            var text = VpnService.ReadLogs().Trim();
            var dialog = new ContentDialog
            {
                Title = "log",
                Content = new ScrollViewer
                {
                    MaxHeight = 480,
                    Content = new TextBlock
                    {
                        Text = text.Length == 0 ? "(empty)" : text,
                        TextWrapping = TextWrapping.Wrap,
                        FontSize = 12,
                        IsTextSelectionEnabled = true,
                    },
                },
                PrimaryButtonText = "close",
            };
            await dialog.ShowAsync();
        }

        private void ClearLog_Click(object sender, RoutedEventArgs e)
        {
            VpnService.ClearLogs();
        }

        // ---------- helpers ----------

        private async Task RunBusyAsync(Func<Task> action)
        {
            Busy.Visibility = Visibility.Visible;
            ConnectButton.IsEnabled = false;
            try
            {
                await action();
            }
            catch (Exception ex)
            {
                await ShowMessageAsync(ex.Message);
            }
            finally
            {
                Busy.Visibility = Visibility.Collapsed;
                ConnectButton.IsEnabled = true;
                await RefreshStatusAsync();
            }
        }

        private static async Task ShowMessageAsync(string message)
        {
            await new MessageDialog(message, "xelite").ShowAsync();
        }

        private static InputScope UrlScope()
        {
            var scope = new InputScope();
            scope.Names.Add(new InputScopeName(InputScopeNameValue.Url));
            return scope;
        }
    }
}
